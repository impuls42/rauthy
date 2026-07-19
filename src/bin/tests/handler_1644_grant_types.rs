use crate::common::get_backend_url;
use pretty_assertions::assert_eq;
use rauthy_api_types::clients::DynamicClientRequest;
use std::error::Error;

mod common;

// -----------------------------------------------------------------------------------------
// #1644 - grant types are opt-in; Dynamic Client Registration stays strict and REJECTS an
// unsupported grant.
//
// `POST /clients_dyn` stores the advertised `grant_types` verbatim as the client's enabled
// flows, so an unknown/unsupported grant type must be rejected up front rather than persisted
// as a dead flow. `urn:ietf:params:oauth:grant-type:jwt-bearer` is not supported by Rauthy and
// must yield a 400. (The ephemeral/CIMD opt-in ACCEPT path - which *strips* unknown grants when
// `ephemeral_clients.ignore_unknown_auth_flows` is enabled - fetches a hosted CIMD document and
// is exercised by a separate live/real-env test; it is not driven here.)
//
// Without the fix (strict `validate_vec_grant_types`), the jwt-bearer grant would pass
// validation and this request would be accepted (201) instead of rejected (400).
// -----------------------------------------------------------------------------------------
#[tokio::test]
async fn test_1644_dcr_rejects_unsupported_grant() -> Result<(), Box<dyn Error>> {
    let backend_url = get_backend_url();
    let http = reqwest::Client::new();

    let payload = DynamicClientRequest {
        redirect_uris: vec!["http://localhost:8080/*".to_string()],
        grant_types: vec![
            "authorization_code".to_string(),
            // unsupported by Rauthy -> DCR must reject the whole request
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        ],
        client_name: Some("Dyn JWT Bearer Reject".to_string()),
        client_uri: None,
        contacts: None,
        id_token_signed_response_alg: None,
        token_endpoint_auth_method: Some("none".to_string()),
        token_endpoint_auth_signing_alg: None,
        post_logout_redirect_uri: None,
        backchannel_logout_uri: None,
    };
    let res = http
        .post(format!("{backend_url}/clients_dyn"))
        .json(&payload)
        .send()
        .await?;
    // `payload.validate()` runs before the IP rate-limit, so this is a deterministic 400
    assert_eq!(res.status(), 400);

    Ok(())
}
