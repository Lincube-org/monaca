<!-- 本文档是 monaca 已批准的 M0–M4 架构计划（approved architecture），逐字复制自 approved plan，仅在顶部增加本说明行。 -->

# Monaca — 面向 AI Agent 时代的全栈 IAM：架构与首期计划（已批准：M0–M4）

> 状态：**已批准（approved）**。本文档是 monaca 的架构权威来源（authoritative plan），覆盖里程碑 **M0–M4**。
> 逐字复制自已批准的架构计划，不在此处修改内容；如需变更请走 docs/adr/ 并同步更新本文档。

---

# Monaca — 面向 AI Agent 时代的全栈 IAM：架构与首期计划

## Context

仓库 `C:\git\sso\monaca` 目前是空的（只有 `.gitignore`/`.gitattributes`，没有 remote）。目标是从零构建一套**面向开发者、面向 AI agent 时代的身份与访问管理系统**：

- **定位（已确认）**：三者合一的全栈 IAM，包含协议引擎（OIDC/OAuth 2.1，后续 SAML/SCIM）、开发者平台（SDK、托管登录页、控制台）和 agent 原生授权层（委托链、权限衰减、审批、审计取证）。分期推进：M0 行走骨架 → M1 OIDC 基线 → M2 开发者平台 → M3 agent 深度 → M4 联邦与企业。
- **技术栈（已确认）**：Rust 作为核心，负责性能与安全；Bun 负责上层模块的组合；PostgreSQL；前端用 Vue 3 + shadcn-vue + Vite。
- **Rust/Bun 边界（已确认）**：混合。热路径（验签、策略求值）通过 napi-rs 在进程内调用；协议端点和身份数据写入放在独立的 axum 服务里，做到崩溃隔离。
- **租户模型（已确认）**：**一个租户 = 一个 database，一个组织 = 该库中的一个 schema**，外加一个控制面库。
- **构建与验证（已确认）**：Rust 只在 GitHub Actions 里编译，本机不装 Rust 工具链。本地验证方式由开发者自选，三种模式（本地全栈 / 连远程 dev 环境 / 纯 CI）。
- **首期（M0）验收（已确认）**：端到端行走骨架。建用户 → 注册 agent → 授予 `tools:read` → agent 用自己的密钥换到委托 token → 调用 MCP 工具成功，越权 scope 被拒 → 审计页能看到完整的 `user→agent→tool` 委托链。

产品名沿用目录名 **monaca**：crate 前缀为 `monaca-*`，npm scope 为 `@monaca/*`。

---

## 1. 分工铁律（整套架构的承重规则）

| 归属 | 内容 |
|---|---|
| **Rust** | 凡是签发或验证凭证、接触密钥与秘密、写入身份数据（system of record）、运行协议状态机、维护审计链的，都归 Rust |
| **Bun** | 组合与集成：边缘路由与 BFF、可插拔模块（webhooks、邮件短信、SAML/SCIM 适配、MCP 服务、分析）、SDK、托管 UI 的分发 |
| **契约** | 三类契约全部**由 Rust 生成，绝不手写 TS**：① HTTP 用 OpenAPI（utoipa）；② 进程内调用用 napi 类型定义（napi-rs 生成的 `index.d.ts`）；③ 事件用 JSON Schema（schemars） |

由此推出几条硬约束：
- 身份核心表**只有 Rust 写**。Bun 模块只能写自己的 `mod_<name>_*` 表；读核心数据、写审计，都走 Rust API。
- napi 原生模块**不做任何 I/O**（不连库、不发网络、不起 tokio），只放纯函数和本地缓存（密钥集、策略集、吊销集）。缓存由 TS 侧拉取后推入。这样原生崩溃面最小，也不会出现两套连接池互相争抢。
- 选型时 Rust 生态弱的地方交给 Bun。例如 SAML：Rust 的 `samael` 依赖 libxml2/xmlsec，在 Windows 上很痛苦，可以改在 Bun 模块里用成熟的 npm 库实现，校验完成后再调 Rust API 落库。这正好是混合架构"可自由组合"的用武之地。

## 2. 运行时拓扑

```
                 ┌──────────── 生产：边缘按路径分流（M1 起，Caddy/Envoy）────────────┐
 浏览器 / Agent ─┤ /oauth2/* /.well-known/* /interaction/*  ──────────► monaca-server (Rust/axum)
                 │ 其余（/bff/* /mcp/* /v1 模块路由 静态 UI） ──► monaca-gateway (Bun/Hono)
                 └──────────────────────────────────────────────────────────────────────┘
 monaca-gateway ──napi──► @monaca/core (.node)   验签 / scope 判定 / (M1) Cedar 策略 / (M1) DPoP
 monaca-gateway ──HTTP──► monaca-server /v1/* 管理 API、/internal/* (审计写入、事件流、配置同步)
 monaca-server  ──sqlx──► PG：control 库 + 各租户库
 monaca-gateway ──Bun.sql► PG：仅限模块自有表（经同一套租户/组织路由）
```

M0 为了简单，由 gateway 用 `MONACA_DEV_PROXY` 统一代理到 server，只有一个 origin。M1 再引入边缘分流配置，让协议端点不依赖 gateway 进程。

## 3. 多租户与数据模型（租户 = DB，组织 = schema）

```
monaca_control (DB)
  clusters(id, admin_dsn_enc, app_dsn_enc, region, capacity)      -- 可注册多个 PG 集群
  tenants(id, slug, cluster_id, db_name, issuer, state)           -- state: provisioning|active|suspended
  platform_admins, migration_rollup

mt_<tenant_short> (每租户一个 DB)
  schema tenant      -- 固定名，SQL 中一律写全限定名 tenant.*
    accounts, account_identifiers, credentials(password|passkey|totp), sessions
    clients, redirect_uris, signing_keys(enc), auth_codes, refresh_tokens
    organizations(id, slug, schema_name, role_name, state)
    audit_events(租户级链：登录、账号事件), outbox, _migrations
  schema org_<org_short>   -- 每组织一个，SQL 中不写限定名，靠 search_path 解析
    members(account_id, role), agents, agent_keys, grants, delegations, approvals
    policies(Cedar, M1), audit_events(组织级哈希链), mod_<module>_*（模块自有表）, _migrations
```

- **身份放在租户级，权限放在组织级**：账号和凭证在 `tenant` schema，一个人用一套登录就能加入多个组织；成员关系、agent、授权、策略、审计都在 `org_*` schema 里物理隔离。token 用 `org` claim 指明当前组织。签名密钥和 issuer 按租户划分。
- **每个事务的隔离方式**：`BEGIN; SET LOCAL search_path = org_x; SET LOCAL ROLE <org 角色>;`。每个组织有一个独立 PG 角色，只对自己的 schema 和 `tenant.*` 中必要的表有权限；运行时角色 `monaca_app` 是各组织角色的成员。这样即使 search_path 设错，也会被权限挡住（纵深防御）。PG 角色是集群级的，所以角色名统一采用 `t<租户短ID>_o<组织短ID>`。
- **建租户是一个 saga**：`CREATE DATABASE` 不能放在事务里，所以用状态机 `provisioning→active`，每步幂等、可重试。**建组织**放在单个事务里完成：CREATE SCHEMA、CREATE ROLE、跑 org 迁移、登记组织。所有标识符都用短 ID 并经 `quote_ident`，绝不拼接用户输入。
- **连接池**：每个租户库对应一个小池，用 LRU 缓存（上限可配，空闲回收）；规模上来后在前面加 PgBouncer 事务模式，`SET LOCAL` 与它兼容。租户和组织的路由表在进程内缓存。
- **迁移**：分三套，`control`、`tenant`、`org`（模板）。由 Rust 编排器逐库、逐 schema 应用，每个 schema 自带 `_migrations` 账本，控制面另存一份汇总。全程遵守 expand/contract，应用代码同时兼容 N 与 N+1 版本。模块迁移（`mod_*` 的 SQL 文件）也交给同一个编排器。
- **ID**：内部用应用侧生成的 UUIDv7（Rust `uuid` v7），因此 PG 16+ 即可，CI 使用 18。对外暴露带类型前缀的 ID，如 `usr_…`、`agt_…`、`grt_…`、`org_…`。
- **SQL 访问**：使用 sqlx **运行时**查询（`query_as` + `FromRow`），不用 `query!` 宏。理由：本地不编译，编译期检查和集成测试都在同一轮 CI 里给出反馈，宏不会带来提速，却要求 Windows 构建任务额外拿到 `.sqlx` 离线数据。改由 `#[sqlx::test]` 覆盖每一条查询。

## 4. Rust workspace（`crates/`）

| crate | 职责 |
|---|---|
| `monaca-types` | 类型化 ID 及前缀编解码、`TenantCtx`/`OrgCtx`、RFC 9457 problem 错误模型、时钟抽象 |
| `monaca-crypto` | JWS（`jsonwebtoken`，后端用 RustCrypto，Windows 友好；`aws-lc-rs` 作为 FIPS 特性开关）、ES256/EdDSA 密钥、argon2id（`spawn_blocking` 加并发上限）、信封加密（租户 DEK 由 KEK 加密，`KeyProvider` trait：dev 读环境变量，生产接 KMS/Vault）、`subtle` 常量时间比较、WebAuthn 注册/断言校验（`none` attestation + ES256） |
| `monaca-store` | control/tenant/org 三套迁移、编排器、租户/组织 provisioner、路由缓存、`with_org_tx(ctx, fn)`、outbox |
| `monaca-oidc` | discovery（同时提供 RFC 8414 的 `/.well-known/oauth-authorization-server/t/{tenant}` 和 OIDC 的 `/t/{tenant}/.well-known/openid-configuration`）、JWKS、authorize + interaction、code+PKCE（强制）、refresh、client_credentials、`private_key_jwt`、RAR（RFC 9396）、id_token。M1 增加 PAR/DPoP/内省/吊销 |
| `monaca-agent` | agent 注册表、grant、**权限衰减代数**（scope 只交不并、aud 只收窄、exp 只缩短、深度上限），委托 token 铸造（嵌套 `act`）。M3 增加 RFC 8693 多跳交换和 CIBA |
| `monaca-policy` | M0 只有 scope 判定；M1 接入 Cedar（`cedar-policy`），按组织维护策略集并做版本化 |
| `monaca-audit` | 每组织一条哈希链：`hash = SHA256(prev_hash ‖ JCS(event))`，与业务写入同事务（锁链头行）；提供校验器 |
| `monaca-core` | 无 I/O 的门面，汇集 napi 需要的纯逻辑（验签、claims 解析、scope 判定、M1 的 Cedar） |
| `monaca-napi` | napi-rs v3 绑定，产出 `@monaca/core` 的 `.node` 和生成的 `index.js`/`index.d.ts` |
| `monaca-server` | axum 0.8 二进制：公共协议路由、`/v1` 管理 API（utoipa 生成 OpenAPI）、`/internal/*`（M0 用共享密钥，M1 改 mTLS）、tracing+OTLP、tower 限流与超时；子命令 `migrate`/`bootstrap`/`audit verify`/`openapi` |

## 5. Agent 委托模型（差异化核心）

- **Agent 是一等主体**：属于某个组织，归属一个账号；凭证是一对密钥，公钥登记在服务端，**私钥从不经过服务端**。M0 由控制台用 WebCrypto 在浏览器生成并下载 JWK。
- **Grant**：`delegator(账号) → agent`，字段包括 `{scopes, resource(aud), constraints, expires_at}`。M0 由组织管理员代为创建（企业场景下由管理员下发 agent 权限）；M1/M3 改为用户自己通过同意页或 CIBA 授权。
- **换取委托 token（M0）**：agent 用 `private_key_jwt` 认证，走 `client_credentials` 并附带 `resource`（RFC 8707）、`scope` 和 `authorization_details=[{type:"monaca_grant",grant_id}]`（RFC 9396）。服务端校验 grant 有效，并要求请求的 scope ⊆ grant，否则返回 `invalid_scope`。签发的 token 为 `sub=账号, act={sub:agent}, org, scope, aud, grant_id, jti`，TTL 5 分钟。整个过程写入审计。
- **多跳（M3）**：RFC 8693 token exchange，`subject_token` 为上一跳的 token，`actor_token` 为子 agent 的断言，生成嵌套 `act`。每一跳都由 `monaca-agent::attenuate` 保证单调收窄，用 proptest 做性质测试：任意链路上子权限都 ⊆ 父权限。
- **吊销**：吊销 grant 后，其所有后代 token 失效。手段是短 TTL，加上向各验证端推送 `grant_id` 吊销集（M3，SSE）。
- **MCP**：受保护的 MCP 服务就是 OAuth 资源服务器。`@monaca/mcp` 守卫负责：提供 RFC 9728 Protected Resource Metadata，用原生 Verifier 验 bearer，按工具声明所需 scope，不满足时返回 `403 insufficient_scope` 和 `WWW-Authenticate`，并把每次工具调用通过 `/internal/audit` 写入审计链。

## 6. Bun 侧（`packages/`、`modules/`、`apps/gateway`）

- **`@monaca/core`**：napi 包。加载与平台匹配的 `.node`，类型来自 napi-rs 生成的 `index.d.ts`。M0 暴露的 API：
  ```ts
  class Verifier { setKeys(issuer, jwksJson); verifyAccessToken(token, {issuer, audience}): VerifiedToken }
  function scopeSatisfies(granted: string[], required: string[]): boolean
  // VerifiedToken: { sub, tid, org, scope, act?, grantId?, jti, exp }
  // M1 增加 verifyDpop、Authorizer(Cedar)；M2 用 wasm 构建覆盖 edge/浏览器
  ```
- **`@monaca/kernel`**：模块系统。`defineModule({ name, version, dependsOn, routes(app), hooks, events, migrations, permissions })`，按依赖拓扑启动，提供生命周期 init/start/stop 和类型化 DI 注册表。注入的 `ctx.db` 已完成租户/组织路由（`Bun.sql`）；`ctx.audit()` 走 Rust API；`ctx.verifier` 来自 `@monaca/core`。事件订阅和同步 hooks（带超时预算与失败策略）在 M2 实现。M0 只往 outbox 写入，relay 在 M2 加上：提交后进程内立即唤醒，再加低频巡检兜底。
- **`apps/gateway`**：Hono on Bun，负责模块宿主、控制台 BFF（token 只放服务端，浏览器只拿 `__Host-` httpOnly 会话 cookie）、JWKS 同步进原生 Verifier，以及 dev 代理。
- **`@monaca/sdk`**：由 `openapi-typescript` 加 `openapi-fetch` 从 `spec/openapi.json` 生成，另带 agent 辅助函数（签 `private_key_jwt` 断言、换取委托 token）。
- **`@monaca/mcp`** 是 MCP 资源服务器守卫。**`modules/mcp-demo`** 是演示用 MCP 服务（官方 `@modelcontextprotocol/sdk`，Streamable HTTP），挂载在 `/mcp/demo`，包含两个工具：`list_notes` 需要 `tools:read`，`delete_note` 需要 `tools:write`。

## 7. 前端（`apps/console`、`apps/auth-ui`、`packages/ui`）

- 技术栈：Vue 3.5、Vite、TS、shadcn-vue（reka-ui）、Tailwind v4、vue-router、`@tanstack/vue-query` 管服务端状态、Pinia 只放少量 UI 状态、vee-validate + zod、TanStack Table。
- **`packages/ui`**：shadcn-vue 组件（用 CLI 生成到包内）、设计 token（CSS 变量，便于按租户换品牌色），以及领域组件 `DelegationChain`、`ScopeBadge`、`KeyFingerprint`、`AuditTimeline`。
- **`apps/auth-ui`**：托管登录页（M0 只有 sign-in），对接 Rust 的 interaction API。协议引擎和 UI 解耦，与 Hydra 的 login/consent challenge 模式类似。
- **`apps/console`**：自己就是一个 OIDC 客户端，经 gateway BFF 走 code+PKCE 登录系统租户（dogfooding）。M0 页面：成员与账号、Agents（浏览器生成密钥）、Grants、审计（按组织展示委托链和链完整性 ✓）。

## 8. 仓库布局

```
monaca/
├─ Cargo.toml  rust-toolchain.toml        # Rust workspace（只在 CI 编译）
├─ package.json  bunfig.toml              # Bun workspaces
├─ crates/monaca-{types,crypto,store,oidc,agent,policy,audit,core,napi,server}
├─ packages/{core,kernel,sdk,mcp,ui,tsconfig}
├─ modules/mcp-demo
├─ apps/{gateway,console,auth-ui}
├─ spec/openapi.json  spec/events/*.json  # CI 生成 → fetch 回来提交，CI 做漂移校验
├─ examples/agent-demo.ts
├─ scripts/{dev.ts,fetch-native.ts,e2e/skeleton.ts}
├─ deploy/{Dockerfile.server,Dockerfile.gateway,compose.dev.yml}
├─ .github/workflows/{rust.yml,web.yml,e2e.yml,image.yml,deploy-dev.yml}
└─ docs/{adr/,threat-model.md}
```

`.gitignore` 需要补上：`node_modules/`、`dist/`、`.monaca/`、`.env*`（保留 `.env.example`）、`*.node`、`playwright-report/`、`test-results/`。

## 9. CI 与三种本地验证模式

**GitHub Actions**（优化目标是缩短 Rust 反馈回路，因为本机不编译）：
- `rust.yml`：
  - `check` 任务：fmt + clippy，用 `Swatinem/rust-cache` 和 `paths` 过滤，目标是热缓存 2–3 分钟内出结果。
  - `test` 任务：ubuntu，`services: postgres:18`，跑 `cargo nextest`。
  - `build` 矩阵：`x86_64-pc-windows-msvc`（windows-latest）和 `x86_64-unknown-linux-gnu`，产出 `monaca-server` 可执行文件和 napi `.node`。
  - `codegen` 任务：产出 `openapi.json`、事件 schema、napi `index.{js,d.ts}`。
  - 以上全部 `upload-artifact`。
  - 漂移校验：已提交的生成物必须与 CI 生成的一致。
- `web.yml`：bun install、typecheck、`bun test`、vite build。
- `e2e.yml`：依赖 build 产物。ubuntu + PG 服务，启动 server 和 gateway，运行 `scripts/e2e/skeleton.ts` 和 Playwright 控制台流程，上传报告和 trace。
- `image.yml`：main 分支构建 linux 镜像推送到 GHCR。`deploy-dev.yml`：用 SSH + docker compose 部署到一台 VPS，没配 secrets 时自动跳过，模式 B 依赖它。

**`bun run dev`** 第一次运行时让开发者选择模式，选择记在 `.monaca/dev.json`，之后可用 `--mode` 覆盖：

| 模式 | 本地运行什么 | Rust 产物 / PG |
|---|---|---|
| **A 本地全栈** | server.exe + gateway + console + auth-ui | `bun run fetch:native` 用 `gh run download` 拉当前提交的 CI 产物。PG 优先用 `DATABASE_URL`（需要 CREATEDB/CREATEROLE 权限）；没设置就用 `embedded-postgres` 下载真实 PG 二进制到 `.monaca/pg`，无需 Docker 和管理员权限 |
| **B 远程 dev** | 只跑 Vue 应用（Vite 代理到远程 gateway）；`--with-gateway` 可在本地跑 gateway 开发模块 | `deploy-dev.yml` 部署到 VPS，需要一台主机及对应 secrets |
| **C 纯 CI** | 本地只跑 typecheck 和 TS 单测 | push 后由 `bun run verify:ci` 调 `gh workflow run` 加 `gh run watch`，结果和 Playwright 报告从 artifact 查看 |

三种模式都使用**同一个**验收脚本 `scripts/e2e/skeleton.ts --base-url <url>`，与目标环境无关。

## 10. M0 行走骨架——执行顺序（风险最高的先做）

0. **建仓与 CI 打通**：创建 GitHub 私有仓库并推送（owner、仓库名、可见性在执行前与用户确认；当前 gh 账号是 `wwiinnddyy`，git user 是 `lincube`）。搭 Cargo 和 Bun 两套 workspace 骨架、补全 `.gitignore`、写好全部 workflow，用 hello-world 级别的 server、napi 和 Vue 先让 CI 全绿。
1. **先行 spike**，用 CI 和本地共同验证：
   - Bun 1.3 在 win32-x64 与 linux-x64 上加载 napi-rs v3 产出的 `.node`，包括 class、抛出的错误、`Buffer`；
   - `embedded-postgres` 在 Windows + Bun 下能启动；
   - MCP TS SDK 的 Streamable HTTP 能在 Bun/Hono 上跑。

   任何一项失败，都先调整方案，再继续后面的步骤。
2. **存储与租户**：三套迁移和编排器，租户 saga 与组织 provisioner，`with_org_tx`，`monaca-server bootstrap` 写入种子数据（系统租户及管理员、`demo` 租户、`acme` 组织）。
3. **密码学与密钥**：KeyProvider（dev 用 KEK）、按租户的 ES256 密钥、JWKS、argon2id。
4. **OIDC 最小集**：discovery（两种路径形式）、authorize、interaction API、code+PKCE、token（authorization_code / refresh / client_credentials + `private_key_jwt` + RAR）、id_token。
5. **Agent 与审计**：agents、agent_keys、grants 的表和 `/v1` API；委托 token（scope 求交、嵌套 `act`）；组织级哈希链；`/internal/audit` 写入；`audit verify`。
6. **契约生成**：utoipa 输出 OpenAPI，`@monaca/sdk` 据此生成；napi 绑定生成 `@monaca/core`。
7. **Bun**：kernel、gateway（BFF、JWKS 同步、dev 代理）、`@monaca/mcp`、`modules/mcp-demo`。
8. **前端**：`packages/ui`、`apps/auth-ui`（sign-in）、`apps/console`（登录、成员、Agents、Grants、审计链视图）。
9. **验收自动化**：`examples/agent-demo.ts`、`scripts/e2e/skeleton.ts`、Playwright 控制台流程、`e2e.yml`。

## 11. 后续里程碑（概要）

- **M1 OIDC 基线**：完整 OIDC Core（nonce/prompt/max_age/userinfo）、refresh 轮换与重用检测、PAR、DPoP（agent token 强制绑定发送方）、内省与吊销、密钥自动轮换、passkey（`monaca-crypto` 内自研 WebAuthn 校验：COSE/ES256 + 最小 CBOR，不引入 `webauthn-rs`）与 TOTP、邮件模块（验证邮件与魔法链接）、Cedar 同时进 napi 与 server、限流和暴力破解防护、边缘分流、内部通信改 mTLS、通过 OpenID 官方 conformance suite（Basic/Config OP），控制台增加客户端、密钥、会话页面。
- **M2 开发者平台**：SDK 流水线、`@monaca/node` 与框架适配器、`@monaca/vue` 可嵌入组件、按租户品牌化托管页、组织邀请、API key、同步 hooks（Actions）、webhooks 模块（outbox relay + 事件订阅）、DCR 与 Client ID Metadata、wasm 版 core（edge/浏览器）、文档站。
- **M3 Agent 深度**：CIBA 人在回路审批、多跳 8693 与深度上限、吊销集推送到验证端、MCP 网关模块（按工具配 Cedar 策略、逐次调用审计）、工作负载身份联邦（RFC 7523：GitHub Actions、K8s、云厂商 OIDC 签发的 token 换 agent 身份）、可选 Biscuit 离线衰减凭证、审计检查点签名与委托图浏览器、审计链批量封签（缓解链头锁竞争）。
- **M4 联邦与企业**：上游 OIDC 与社交登录、SAML（Bun 模块）、SCIM 2.0（Bun 模块调 Rust API）、租户跨集群迁移与数据驻留、Helm、HA、备份与 PITR 指南。

## 12. 主要风险

1. **napi-rs × Bun 兼容性**：通过第 1 步 spike 验证。M0 的原生面只有同步纯函数，风险较小。
2. **只在 CI 编译 Rust，反馈慢**：每次 Rust 改动都要一轮 CI。缓解办法：check 任务独立且有缓存、`paths` 过滤、Rust 改动成批提交。
3. **每个租户一个 DB 带来的连接数与运维成本**：LRU 小池加 PgBouncer；控制面登记多个集群，可横向扩展。
4. **组织数量增长导致 PG 角色和 schema 膨胀**：角色是集群级的。纵深防御的 `SET ROLE` 做成可配置项；在 docs/adr 里写明单库 schema 数量的经验上限。
5. **审计链头锁**：组织内写入会串行化。M0 可接受，M3 改为批量 Merkle 封签。
6. **协议正确性**：M1 用 conformance suite 和对解析器的 cargo-fuzz 兜底。

## 13. 验证（M0 完成判定）

- **CI（模式 C，权威判定）**：`rust`、`web`、`e2e` 三条 workflow 全绿。`e2e` 的产物中，`skeleton.ts` 必须逐条通过：
  ① 健康检查；
  ② 用管理 API 建账号，加入 `acme`，注册 agent，授予 `tools:read`；
  ③ agent 用 `private_key_jwt` 加 RAR 换到 token，token 中带 `act.sub=agt_…`、`scope=tools:read`；请求 `tools:write` 时 token 端点返回 `invalid_scope`；
  ④ 调用 `list_notes` 成功，调用 `delete_note` 返回 `403 insufficient_scope`；
  ⑤ `GET /v1/orgs/acme/audit` 能看到 `account → grant → agent → token(jti) → tool` 的完整链，且 `audit verify` 返回链完整。

  同时 Playwright 在控制台走一遍②和⑤的 UI 流程。
- **Rust 测试**：`#[sqlx::test]` 覆盖每条查询，以及租户/组织 provisioning 和跨组织访问被权限拒绝；proptest 覆盖衰减单调性和哈希链篡改检测；`bun test` 中对比 napi 验签与 `jose` 的结果（差分测试）。
- **模式 A / B**：开发者选好模式后执行 `bun run dev`，手动走一遍控制台流程，然后用 `bun run e2e:skeleton --base-url <本地或远程>` 跑同一个验收脚本。
