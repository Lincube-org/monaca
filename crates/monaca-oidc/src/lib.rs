//! The OpenID Connect and OAuth 2.1 protocol engine: discovery, authorize, interaction,
//! token and id_token.
//!
//! The split this crate encodes is the one that makes the auth-ui possible at all: the protocol
//! engine owns the flow, and the UI only ever sees an [`InteractionApi`] handle. That is the
//! Hydra-style login/consent challenge pattern — `authorize` stores an interaction and 302s to
//! the hosted sign-in page with `int_…`, and the page calls back into the interaction API. The
//! interaction id is the bearer of the request, which is why it is high-entropy and single-use.
//!
//! **What lives here is pure.** Request validation, the discovery document, PKCE, the claim
//! shapes and the client-assertion rules. Storage, keys and HTTP are the caller's; keeping the
//! protocol arithmetic free of I/O is what lets it be tested against the contract's vectors
//! without a database.
//!
//! M1 adds PAR, DPoP, introspection, revocation, nonce enforcement and `at_hash`.

mod authorize;
mod discovery;
mod interaction;
mod token;

pub use authorize::{AuthorizeError, AuthorizeParams, AuthorizeRequest, is_absolute_http_url};
pub use discovery::DiscoveryDocument;
pub use interaction::{Interaction, InteractionError};
pub use token::{
    AccessTokenClaims, AssertionError, ClientAssertion, GrantType, IdTokenClaims, TokenErrorCode,
    TokenForm, TokenRequest, validate_assertion_claims,
};

/// Verify a PKCE `S256` challenge — RFC 7636 §4.6.
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    use sha2::{Digest, Sha256};

    // RFC 7636 §4.1: 43..128 characters from the unreserved set.
    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return false;
    }
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = data_encoding::BASE64URL_NOPAD.encode(&digest);
    // Constant-time is not required here (the challenge is public and single-use), but comparing
    // the digest strings is what the RFC specifies and avoids a prefix oracle all the same.
    subtle_eq(computed.as_bytes(), code_challenge.as_bytes())
}

fn subtle_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// The valid scope grammar — §6.2: `^[a-z][a-z0-9_.-]*(:[a-z][a-z0-9_.-]*)*$`.
pub fn valid_scope(scope: &str) -> bool {
    if scope.is_empty() {
        return false;
    }
    scope.split(':').all(|part| {
        let mut chars = part.chars();
        match chars.next() {
            Some(first) if first.is_ascii_lowercase() => {}
            _ => return false,
        }
        chars.all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-')
        })
    })
}

/// Parse a space-delimited `scope` parameter, dropping empties and de-duplicating.
pub fn parse_scope(raw: &str) -> Vec<String> {
    let mut scopes: Vec<String> = raw.split_ascii_whitespace().map(str::to_owned).collect();
    scopes.sort_unstable();
    scopes.dedup();
    scopes
}

/// The space-delimited wire form of a scope set.
pub fn scope_string(scopes: &[String]) -> String {
    scopes.join(" ")
}

/// Whether `requested` is a subset of `allowed` (set semantics).
pub fn scope_subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|scope| allowed.contains(scope))
}

/// Intersect two scope sets, sorted.
pub fn scope_intersection(left: &[String], right: &[String]) -> Vec<String> {
    let mut out: Vec<String> = left
        .iter()
        .filter(|scope| right.contains(scope))
        .cloned()
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B.
    #[test]
    fn the_rfc7636_vector_verifies() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(verifier, challenge));
        assert!(!verify_pkce_s256(
            verifier,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    #[test]
    fn a_short_verifier_is_refused() {
        assert!(!verify_pkce_s256("short", "x"));
    }

    #[test]
    fn scopes_are_split_sorted_and_deduplicated() {
        assert_eq!(
            parse_scope("  tools:read  openid tools:read "),
            vec!["openid", "tools:read"]
        );
        assert!(parse_scope("").is_empty());
    }

    #[test]
    fn the_scope_grammar_matches_the_contract() {
        for scope in [
            "openid",
            "tools:read",
            "tools:write",
            "monaca:admin",
            "a.b-c_d",
        ] {
            assert!(valid_scope(scope), "{scope} must be valid");
        }
        for scope in ["", "Tools:read", "tools:", ":read", "tools read", "1tools"] {
            assert!(!valid_scope(scope), "{scope} must be invalid");
        }
    }

    #[test]
    fn subset_and_intersection_agree() {
        let allowed = vec!["openid".to_owned(), "tools:read".to_owned()];
        let requested = vec!["tools:read".to_owned()];
        assert!(scope_subset(&requested, &allowed));
        assert_eq!(scope_intersection(&allowed, &requested), requested);

        let wider = vec!["tools:write".to_owned(), "tools:read".to_owned()];
        assert!(!scope_subset(&wider, &allowed));
    }
}
