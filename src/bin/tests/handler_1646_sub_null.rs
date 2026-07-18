use crate::common::{CLIENT_ID, CLIENT_SECRET, get_backend_url};
use pretty_assertions::assert_eq;
use rauthy_api_types::oidc::TokenRequest;
use rauthy_common::utils::base64_url_no_pad_decode;
use rauthy_service::token_set::TokenSet;
use std::error::Error;

mod common;

/// Decodes the (unverified) JWT payload into raw JSON claims, so the test can inspect the
/// presence/absence of a claim key (not just its value).
fn decode_payload(token: &str) -> serde_json::Value {
    let payload_b64 = token.split('.').nth(1).expect("a JWT payload segment");
    let bytes = base64_url_no_pad_decode(payload_b64).expect("valid base64url payload");
    serde_json::from_slice(&bytes).expect("valid JSON claims")
}

// -----------------------------------------------------------------------------------------
// #1646 - `client_credentials` access tokens must NOT serialize a `sub` claim at all.
//
// A `client_credentials` token has no end-user subject. Before the fix the `sub` claim was
// serialized as an explicit JSON `null` (`"sub": null`), which trips strict OIDC/JWT consumers
// that require `sub` to be a string when present. The fix marks the claim
// `#[serde(skip_serializing_if = "Option::is_none")]`, so the key is now ABSENT entirely.
//
// Without the fix this test fails: `claims.get("sub")` would return `Some(Value::Null)` instead
// of `None`, so `assert!(claims.get("sub").is_none())` panics.
// -----------------------------------------------------------------------------------------
#[tokio::test]
async fn test_1646_client_credentials_sub_absent() -> Result<(), Box<dyn Error>> {
    let backend_url = get_backend_url();
    let http = reqwest::Client::new();

    // `init_client` is seeded with the `client_credentials` flow enabled, so we can fetch a
    // subject-less access token directly.
    let body = TokenRequest {
        grant_type: "client_credentials".to_string(),
        code: None,
        redirect_uri: None,
        client_id: Some(CLIENT_ID.to_string()),
        client_secret: Some(CLIENT_SECRET.to_string()),
        code_verifier: None,
        device_code: None,
        username: None,
        password: None,
        refresh_token: None,
        resource: None,
    };
    let res = http
        .post(format!("{backend_url}/oidc/token"))
        .form(&body)
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    let ts = res.json::<TokenSet>().await?;

    // a client_credentials grant issues no id/refresh token - only the access token
    assert!(ts.id_token.is_none());
    assert!(ts.refresh_token.is_none());

    let claims = decode_payload(&ts.access_token);
    // sanity: we decoded the payload, not the header
    assert!(claims.get("iss").is_some());
    // the whole point of #1646: the key must be ABSENT, not present-as-null
    assert!(
        claims.get("sub").is_none(),
        "client_credentials token must not serialize a `sub` claim, got: {:?}",
        claims.get("sub")
    );

    Ok(())
}
