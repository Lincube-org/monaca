<script setup lang="ts">
/**
 * The tenant's CAPTCHA widget (§6.1).
 *
 * Turnstile, reCAPTCHA and hCaptcha offer an explicit-render API, so the widget lives exactly where
 * the form puts it instead of injecting itself at load time. Cap is a web component whose endpoint
 * is `{base_url}/{site_key}/`; it is mounted the same way and reports its token through its `solve`
 * event. The token is handed up on success and dropped when the provider expires or errors it; a
 * rejected submit calls `reset()` because tokens are single-use.
 */
import { onBeforeUnmount, onMounted, ref } from "vue";

type Provider = "turnstile" | "recaptcha" | "hcaptcha" | "cap";

const props = defineProps<{
  provider: Provider;
  siteKey: string;
  /** The Cap instance base URL; ignored by the other providers. */
  baseUrl?: string | null;
}>();

const emit = defineEmits<{ "update:token": [token: string | null] }>();

interface Turnstile {
  render: (element: HTMLElement, options: Record<string, unknown>) => string;
  reset: (id: string) => void;
}

interface Recaptcha {
  render: (element: HTMLElement, options: Record<string, unknown>) => number;
  reset: (id: number) => void;
}

interface Hcaptcha {
  render: (element: HTMLElement, options: Record<string, unknown>) => string;
  reset: (id: string) => void;
}

interface CaptchaWindow {
  turnstile?: Turnstile;
  grecaptcha?: Recaptcha;
  hcaptcha?: Hcaptcha;
}

const SCRIPT_SOURCES: Record<Provider, string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  recaptcha: "https://www.google.com/recaptcha/api.js?render=explicit",
  hcaptcha: "https://js.hcaptcha.com/1/api.js?render=explicit",
  cap: "https://cdn.jsdelivr.net/npm/@cap.js/widget",
};

/** The subset of the Cap custom element this page drives. */
interface CapWidget extends HTMLElement {
  reset?: () => void;
}

const container = ref<HTMLDivElement | null>(null);
let widgetId: string | number | null = null;
let capWidget: CapWidget | null = null;

function loadScript(src: string, asModule = false): Promise<void> {
  const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`);
  if (existing) {
    if (existing.dataset.loaded === "true") return Promise.resolve();
    return new Promise((resolve, reject) => {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error("the CAPTCHA script failed to load")), {
        once: true,
      });
    });
  }
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    if (asModule) script.type = "module";
    script.async = true;
    script.defer = true;
    script.addEventListener(
      "load",
      () => {
        script.dataset.loaded = "true";
        resolve();
      },
      { once: true },
    );
    script.addEventListener("error", () => reject(new Error("the CAPTCHA script failed to load")), {
      once: true,
    });
    document.head.appendChild(script);
  });
}

function installed(): CaptchaWindow {
  return window as unknown as CaptchaWindow;
}

const options = {
  sitekey: props.siteKey,
  callback: (token: string) => emit("update:token", token),
  "expired-callback": () => emit("update:token", null),
  "error-callback": () => emit("update:token", null),
};

/** The Cap endpoint the widget solves against: `{base}/{site_key}/`. */
function capEndpoint(): string | null {
  const base = props.baseUrl?.trim().replace(/\/+$/, "");
  return base ? `${base}/${props.siteKey}/` : null;
}

/** Mount Cap's web component; its `solve` event carries the single-use token. */
function mountCap(): void {
  const endpoint = capEndpoint();
  if (!endpoint || !container.value) {
    emit("update:token", null);
    return;
  }
  const widget = document.createElement("cap-widget") as CapWidget;
  widget.setAttribute("data-cap-api-endpoint", endpoint);
  widget.addEventListener("solve", (event) => {
    const token = (event as CustomEvent<{ token?: unknown }>).detail?.token;
    emit("update:token", typeof token === "string" && token !== "" ? token : null);
  });
  widget.addEventListener("error", () => emit("update:token", null));
  widget.addEventListener("reset", () => emit("update:token", null));
  container.value.replaceChildren(widget);
  capWidget = widget;
}

onMounted(async () => {
  try {
    if (props.provider === "cap") {
      await loadScript(SCRIPT_SOURCES.cap, true);
      mountCap();
      return;
    }
    await loadScript(SCRIPT_SOURCES[props.provider]);
    if (!container.value) return;
    const api = installed();
    if (props.provider === "turnstile" && api.turnstile) {
      widgetId = api.turnstile.render(container.value, options);
    } else if (props.provider === "recaptcha" && api.grecaptcha) {
      widgetId = api.grecaptcha.render(container.value, options);
    } else if (props.provider === "hcaptcha" && api.hcaptcha) {
      widgetId = api.hcaptcha.render(container.value, options);
    } else {
      emit("update:token", null);
    }
  } catch {
    emit("update:token", null);
  }
});

onBeforeUnmount(() => {
  widgetId = null;
  capWidget = null;
});

function reset(): void {
  emit("update:token", null);
  if (props.provider === "cap") {
    capWidget?.reset?.();
    return;
  }
  if (widgetId === null) return;
  if (props.provider === "turnstile") {
    installed().turnstile?.reset(String(widgetId));
  } else if (props.provider === "hcaptcha") {
    installed().hcaptcha?.reset(String(widgetId));
  } else {
    installed().grecaptcha?.reset(Number(widgetId));
  }
}

defineExpose({ reset });
</script>

<template>
  <div ref="container" class="flex justify-center" />
</template>
