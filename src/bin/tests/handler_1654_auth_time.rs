use crate::common::{
    PASSWORD, USERNAME, code_state_from_headers, cookie_csrf_headers_from_res_direct,
    get_auth_headers, get_backend_url, get_solved_pow,
};
use pretty_assertions::assert_eq;
use rauthy_api_types::clients::{NewClientRequest, UpdateClientRequest};
use rauthy_api_types::oidc::{JwkKeyPairAlg, LoginRequest, TokenRequest};
use rauthy_common::sha256;
use rauthy_common::utils::{base64_url_encode, base64_url_no_pad_decode};
use rauthy_service::token_set::TokenSet;
use std::error::Error;
use tokio::time;

mod common;

const RID: &str = "auth_time_refresh_test";

/// Returns the `auth_time` claim (unix seconds) from a JWT's (unverified) payload.
fn auth_time_of(token: &str) -> i64 {
    let payload_b64 = token.split('.').nth(1).expect("a JWT payload segment");
    let bytes = base64_url_no_pad_decode(payload_b64).expect("valid base64url payload");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON claims");
    claims
        .get("auth_time")
        .and_then(|v| v.as_i64())
        .expect("`auth_time` claim present")
}

async fn exchange_code(
    http: &reqwest::Client,
    backend_url: &str,
    code: String,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenSet, Box<dyn Error>> {
    let token_req = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code),
        redirect_uri: Some(redirect_uri.to_string()),
        client_id: Some(RID.to_string()),
        client_secret: None,
        code_verifier: Some(code_verifier.to_string()),
        device_code: None,
        username: None,
        password: None,
        refresh_token: None,
        resource: None,
    };
    let res = http
        .post(format!("{backend_url}/oidc/token"))
        .form(&token_req)
        .send()
        .await?;
    assert_eq!(res.status(), 200);
    Ok(res.json::<TokenSet>().await?)
}

// -----------------------------------------------------------------------------------------
// #1654 - OIDC `auth_time` must stay fixed at the real authentication and NOT advance on a
// silent re-auth (`POST /oidc/authorize/refresh`).
//
// `auth_time` is sourced from a session-fixed timestamp. `set_authenticated` runs on both a
// fresh login and a silent re-auth (via `finish_authorize`), so it must only stamp `auth_time`
// on the first authentication. Note the re-issued token in a single silent re-auth still
// captures the correct value (the auth code is built before `set_authenticated` runs), so the
// regression only shows on the SECOND consecutive silent re-auth once the session's stored
// value has been advanced -> this test performs two refreshes.
//
// Without the fix (`set_authenticated` re-stamps unconditionally), the third token's `auth_time`
// equals the first refresh's time rather than the original login time, and the final assertion
// fails. Sleeps force distinct one-second timestamps so the drift is observable.
// -----------------------------------------------------------------------------------------
#[tokio::test]
async fn test_1654_auth_time_stable_across_silent_reauth() -> Result<(), Box<dyn Error>> {
    let backend_url = get_backend_url();
    let auth_headers = get_auth_headers().await?;
    let http = reqwest::Client::new();

    let redirect_uri = "http://localhost:3000/oidc/callback".to_string();
    let challenge_plain = "oDXug9zfYqfz8ejcqMpALRPXfW8QhbKV2AVuScAt8xrLKDAmaRYQ4yRi2uqcH9ys";
    let challenge_s256 = base64_url_encode(sha256!(challenge_plain.as_bytes()));

    // a public PKCE client with authorization_code + refresh_token
    let new_client = NewClientRequest {
        id: RID.to_string(),
        secret: None,
        name: Some("Auth Time Refresh Test".to_string()),
        confidential: false,
        redirect_uris: vec![redirect_uri.clone()],
        post_logout_redirect_uris: None,
    };
    let res = http
        .post(format!("{backend_url}/clients"))
        .headers(auth_headers.clone())
        .json(&new_client)
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    let upd = UpdateClientRequest {
        name: Some("Auth Time Refresh Test".to_string()),
        confidential: false,
        redirect_uris: vec![redirect_uri.clone()],
        post_logout_redirect_uris: None,
        allowed_origins: None,
        enabled: true,
        flows_enabled: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        access_token_alg: JwkKeyPairAlg::EdDSA,
        id_token_alg: JwkKeyPairAlg::EdDSA,
        auth_code_lifetime: 60,
        access_token_lifetime: 300,
        scopes: vec!["openid".to_string()],
        default_scopes: vec!["openid".to_string()],
        challenges: Some(vec!["S256".to_string()]),
        force_mfa: false,
        client_uri: None,
        contacts: None,
        backchannel_logout_uri: None,
        restrict_group_prefix: None,
        claims: None,
        claims_at_root: false,
        allowed_resources: None,
        default_aud: None,
        scim: None,
    };
    let res = http
        .put(format!("{backend_url}/clients/{RID}"))
        .headers(auth_headers.clone())
        .json(&upd)
        .send()
        .await?;
    assert_eq!(res.status(), 200);

    // fresh Init session we will authenticate and then reuse for the silent re-auths
    let res = http
        .post(format!("{backend_url}/oidc/session"))
        .send()
        .await?;
    assert!(res.status().is_success());
    let session_headers = cookie_csrf_headers_from_res_direct(res).await?;

    let query_pkce = format!(
        "client_id={RID}&redirect_uri={redirect_uri}&response_type=code\
        &code_challenge={challenge_s256}&code_challenge_method=S256"
    );
    let url_auth = format!("{backend_url}/oidc/authorize?{query_pkce}");

    // full login -> token1 establishes the reference auth_time (T0)
    let req_login = LoginRequest {
        email: USERNAME.to_string(),
        password: Some(PASSWORD.to_string()),
        pow: get_solved_pow().await,
        client_id: RID.to_string(),
        redirect_uri: redirect_uri.clone(),
        scopes: None,
        state: None,
        nonce: Some("MySuperNonce".to_string()),
        code_challenge: Some(challenge_s256.clone()),
        code_challenge_method: Some("S256".to_string()),
        resource: None,
    };
    let res = http
        .post(&url_auth)
        .headers(session_headers.clone())
        .json(&req_login)
        .send()
        .await?;
    assert_eq!(res.status(), 202);
    let (code, _state) = code_state_from_headers(res)?;
    let ts_login = exchange_code(&http, &backend_url, code, &redirect_uri, challenge_plain).await?;
    let auth_time_login = auth_time_of(ts_login.id_token.as_ref().expect("id_token"));

    let req_refresh = serde_json::json!({
        "client_id": RID,
        "redirect_uri": redirect_uri,
        "nonce": "MySuperNonce",
        "code_challenge": challenge_s256,
        "code_challenge_method": "S256",
    });

    // wait so a re-stamped auth_time would land on a different one-second boundary
    time::sleep(time::Duration::from_secs(2)).await;

    // first silent re-auth -> token2 (still correct even with the bug)
    let res = http
        .post(format!("{backend_url}/oidc/authorize/refresh"))
        .headers(session_headers.clone())
        .json(&req_refresh)
        .send()
        .await?;
    assert_eq!(res.status(), 202);
    let (code2, _s) = code_state_from_headers(res)?;
    let ts2 = exchange_code(&http, &backend_url, code2, &redirect_uri, challenge_plain).await?;
    assert_eq!(
        auth_time_of(ts2.id_token.as_ref().expect("id_token")),
        auth_time_login,
        "auth_time must not change on the first silent re-auth",
    );

    time::sleep(time::Duration::from_secs(2)).await;

    // second silent re-auth -> token3 exposes a re-stamp of the session's stored auth_time
    let res = http
        .post(format!("{backend_url}/oidc/authorize/refresh"))
        .headers(session_headers.clone())
        .json(&req_refresh)
        .send()
        .await?;
    assert_eq!(res.status(), 202);
    let (code3, _s) = code_state_from_headers(res)?;
    let ts3 = exchange_code(&http, &backend_url, code3, &redirect_uri, challenge_plain).await?;
    assert_eq!(
        auth_time_of(ts3.id_token.as_ref().expect("id_token")),
        auth_time_login,
        "auth_time must stay the original login time across repeated silent re-auth (#1654)",
    );

    Ok(())
}
