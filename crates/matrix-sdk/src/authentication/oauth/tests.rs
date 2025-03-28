use std::collections::HashMap;

use anyhow::Context as _;
use assert_matches::assert_matches;
use assert_matches2::assert_let;
use matrix_sdk_test::async_test;
use oauth2::{CsrfToken, PkceCodeChallenge, RedirectUrl};
use ruma::{
    api::client::discovery::get_authorization_server_metadata::msc2965::Prompt, owned_device_id,
    user_id, DeviceId, ServerName,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::sync::broadcast::error::TryRecvError;
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, ResponseTemplate,
};

use super::{
    registrations::OidcRegistrations, AuthorizationCode, AuthorizationError, AuthorizationResponse,
    OAuth, OAuthAuthorizationData, OAuthError, RedirectUriQueryParseError,
};
use crate::{
    authentication::oauth::{
        error::{AuthorizationCodeErrorResponseType, OAuthClientRegistrationError},
        AccountManagementActionFull, AuthorizationValidationData, OAuthAuthorizationCodeError,
    },
    test_utils::{
        client::{
            mock_prev_session_tokens_with_refresh, mock_session_tokens_with_refresh,
            oauth::{mock_client_metadata, mock_redirect_uri, mock_session},
            MockClientBuilder,
        },
        mocks::{oauth::MockServerMetadataBuilder, MatrixMockServer},
    },
    Client, Error, SessionChange,
};

const REDIRECT_URI_STRING: &str = "http://127.0.0.1:6778/oauth/callback";

async fn mock_environment() -> anyhow::Result<(OAuth, MatrixMockServer, Url, OidcRegistrations)> {
    let server = MatrixMockServer::new().await;
    server.mock_who_am_i().ok().named("whoami").mount().await;

    let oauth_server = server.oauth();
    oauth_server.mock_server_metadata().ok().expect(1..).named("server_metadata").mount().await;
    oauth_server.mock_registration().ok().expect(1).named("registration").mount().await;
    oauth_server.mock_token().ok().mount().await;

    let client = server.client_builder().unlogged().build().await;
    let client_metadata = mock_client_metadata();

    let registrations_path =
        tempdir().unwrap().path().join("matrix-sdk-oauth").join("registrations.json");
    let registrations =
        OidcRegistrations::new(&registrations_path, client_metadata, HashMap::new()).unwrap();

    Ok((client.oauth(), server, mock_redirect_uri(), registrations))
}

/// Check the URL in the given authorization data.
async fn check_authorization_url(
    authorization_data: &OAuthAuthorizationData,
    oauth: &OAuth,
    issuer: &Url,
    device_id: Option<&DeviceId>,
    expected_prompt: Option<&str>,
    expected_login_hint: Option<&str>,
) {
    tracing::debug!("authorization data URL = {}", authorization_data.url);

    let data = oauth.data().unwrap();
    let authorization_data_guard = data.authorization_data.lock().await;
    let validation_data =
        authorization_data_guard.get(&authorization_data.state).expect("missing validation data");

    let mut num_expected =
        7 + expected_prompt.is_some() as i8 + expected_login_hint.is_some() as i8;
    let mut code_challenge = None;
    let mut prompt = None;
    let mut login_hint = None;

    for (key, val) in authorization_data.url.query_pairs() {
        match &*key {
            "response_type" => {
                assert_eq!(val, "code");
                num_expected -= 1;
            }
            "client_id" => {
                assert_eq!(val, "test_client_id");
                num_expected -= 1;
            }
            "redirect_uri" => {
                assert_eq!(val, validation_data.redirect_uri.as_str());
                num_expected -= 1;
            }
            "scope" => {
                let expected_start = "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:";
                assert!(val.starts_with(expected_start));
                assert!(val.len() > expected_start.len());

                // Only check the device ID if we know it. If it's generated randomly we don't
                // know it.
                if let Some(device_id) = device_id {
                    assert!(val.ends_with(device_id.as_str()));
                    assert_eq!(val.len(), expected_start.len() + device_id.as_str().len());
                }

                num_expected -= 1;
            }
            "state" => {
                num_expected -= 1;
                assert_eq!(val, authorization_data.state.secret().as_str());
            }
            "code_challenge" => {
                code_challenge = Some(val);
                num_expected -= 1;
            }
            "code_challenge_method" => {
                assert_eq!(val, "S256");
                num_expected -= 1;
            }
            "prompt" => {
                prompt = Some(val);
                num_expected -= 1;
            }
            "login_hint" => {
                login_hint = Some(val);
                num_expected -= 1;
            }
            _ => panic!("unexpected query parameter: {key}={val}"),
        }
    }

    assert_eq!(num_expected, 0);

    let code_challenge = code_challenge.expect("missing code_challenge");
    assert_eq!(
        code_challenge,
        PkceCodeChallenge::from_code_verifier_sha256(&validation_data.pkce_verifier).as_str()
    );

    assert_eq!(prompt.as_deref(), expected_prompt);
    assert_eq!(login_hint.as_deref(), expected_login_hint);

    assert_eq!(authorization_data.url.scheme(), issuer.scheme());
    assert_eq!(authorization_data.url.authority(), issuer.authority());
    assert_eq!(authorization_data.url.path(), "/oauth2/authorize");
}

#[async_test]
async fn test_high_level_login() -> anyhow::Result<()> {
    // Given a fresh environment.
    let (oauth, _server, mut redirect_uri, registrations) = mock_environment().await.unwrap();
    assert!(oauth.issuer().is_none());
    assert!(oauth.client_id().is_none());

    // When getting the OIDC login URL.
    let authorization_data = oauth
        .url_for_oidc(registrations, redirect_uri.clone(), Some(Prompt::Create))
        .await
        .unwrap();

    // Then the client should be configured correctly.
    assert_let!(Some(issuer) = oauth.issuer());
    assert!(oauth.client_id().is_some());

    check_authorization_url(&authorization_data, &oauth, issuer, None, Some("create"), None).await;

    // When completing the login with a valid callback.
    redirect_uri.set_query(Some(&format!("code=42&state={}", authorization_data.state.secret())));

    // Then the login should succeed.
    oauth.login_with_oidc_callback(&authorization_data, redirect_uri).await?;

    Ok(())
}

#[async_test]
async fn test_high_level_login_cancellation() -> anyhow::Result<()> {
    // Given a client ready to complete login.
    let (oauth, _server, mut redirect_uri, registrations) = mock_environment().await.unwrap();
    let authorization_data =
        oauth.url_for_oidc(registrations, redirect_uri.clone(), None).await.unwrap();

    assert_let!(Some(issuer) = oauth.issuer());
    assert!(oauth.client_id().is_some());

    check_authorization_url(&authorization_data, &oauth, issuer, None, None, None).await;

    // When completing login with a cancellation callback.
    redirect_uri.set_query(Some(&format!(
        "error=access_denied&state={}",
        authorization_data.state.secret()
    )));

    let error =
        oauth.login_with_oidc_callback(&authorization_data, redirect_uri).await.unwrap_err();

    // Then a cancellation error should be thrown.
    assert_matches!(
        error,
        Error::OAuth(OAuthError::AuthorizationCode(OAuthAuthorizationCodeError::Cancelled))
    );

    Ok(())
}

#[async_test]
async fn test_high_level_login_invalid_state() -> anyhow::Result<()> {
    // Given a client ready to complete login.
    let (oauth, _server, mut redirect_uri, registrations) = mock_environment().await.unwrap();
    let authorization_data =
        oauth.url_for_oidc(registrations, redirect_uri.clone(), None).await.unwrap();

    assert_let!(Some(issuer) = oauth.issuer());
    assert!(oauth.client_id().is_some());

    check_authorization_url(&authorization_data, &oauth, issuer, None, None, None).await;

    // When completing login with an old/tampered state.
    redirect_uri.set_query(Some("code=42&state=imposter_alert"));

    let error =
        oauth.login_with_oidc_callback(&authorization_data, redirect_uri).await.unwrap_err();

    // Then the login should fail by flagging the invalid state.
    assert_matches!(
        error,
        Error::OAuth(OAuthError::AuthorizationCode(OAuthAuthorizationCodeError::InvalidState))
    );

    Ok(())
}

#[async_test]
async fn test_login_url() -> anyhow::Result<()> {
    let server = MatrixMockServer::new().await;
    let issuer = Url::parse(&server.server().uri())?;

    let oauth_server = server.oauth();
    oauth_server.mock_server_metadata().ok().expect(1..).mount().await;

    let client = server.client_builder().registered_with_oauth(server.server().uri()).build().await;
    let oauth = client.oauth();

    let device_id = owned_device_id!("D3V1C31D"); // yo this is 1999 speaking

    let redirect_uri_str = REDIRECT_URI_STRING;
    let redirect_uri = Url::parse(redirect_uri_str)?;

    // No extra parameters.
    let authorization_data =
        oauth.login(redirect_uri.clone(), Some(device_id.clone()))?.build().await?;
    check_authorization_url(&authorization_data, &oauth, &issuer, Some(&device_id), None, None)
        .await;

    // With prompt parameter.
    let authorization_data = oauth
        .login(redirect_uri.clone(), Some(device_id.clone()))?
        .prompt(vec![Prompt::Create])
        .build()
        .await?;
    check_authorization_url(
        &authorization_data,
        &oauth,
        &issuer,
        Some(&device_id),
        Some("create"),
        None,
    )
    .await;

    // With user_id_hint parameter.
    let authorization_data = oauth
        .login(redirect_uri.clone(), Some(device_id.clone()))?
        .user_id_hint(user_id!("@joe:example.org"))
        .build()
        .await?;
    check_authorization_url(
        &authorization_data,
        &oauth,
        &issuer,
        Some(&device_id),
        None,
        Some("mxid:@joe:example.org"),
    )
    .await;

    Ok(())
}

#[test]
fn test_authorization_response() -> anyhow::Result<()> {
    let uri = Url::parse("https://example.com")?;
    assert_matches!(
        AuthorizationResponse::parse_uri(&uri),
        Err(RedirectUriQueryParseError::MissingQuery)
    );

    let uri = Url::parse("https://example.com?code=123&state=456")?;
    assert_matches!(
        AuthorizationResponse::parse_uri(&uri),
        Ok(AuthorizationResponse::Success(AuthorizationCode { code, state })) => {
            assert_eq!(code, "123");
            assert_eq!(state.secret(), "456");
        }
    );

    let uri = Url::parse("https://example.com?error=invalid_scope&state=456")?;
    assert_matches!(
        AuthorizationResponse::parse_uri(&uri),
        Ok(AuthorizationResponse::Error(AuthorizationError { error, state })) => {
            assert_eq!(*error.error(), AuthorizationCodeErrorResponseType::InvalidScope);
            assert_eq!(error.error_description(), None);
            assert_eq!(state.secret(), "456");
        }
    );

    Ok(())
}

#[async_test]
async fn test_finish_authorization() -> anyhow::Result<()> {
    let server = MatrixMockServer::new().await;
    let oauth_server = server.oauth();

    oauth_server.mock_server_metadata().ok().expect(1..).named("server_metadata").mount().await;
    oauth_server.mock_token().ok().expect(1).named("token").mount().await;

    let client = server.client_builder().registered_with_oauth(server.server().uri()).build().await;
    let oauth = client.oauth();

    // If the state is missing, then any attempt to finish authorizing will fail.
    let res = oauth
        .finish_authorization(AuthorizationCode {
            code: "42".to_owned(),
            state: CsrfToken::new("none".to_owned()),
        })
        .await;

    assert_matches!(
        res,
        Err(OAuthError::AuthorizationCode(OAuthAuthorizationCodeError::InvalidState))
    );
    assert!(client.session_tokens().is_none());

    // Assuming a non-empty state "123"...
    let state = CsrfToken::new("state".to_owned());
    let redirect_uri = REDIRECT_URI_STRING;
    let (_pkce_code_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let auth_validation_data = AuthorizationValidationData {
        redirect_uri: RedirectUrl::new(redirect_uri.to_owned())?,
        pkce_verifier,
    };

    {
        let data = oauth.data().context("missing data")?;
        let prev = data.authorization_data.lock().await.insert(state.clone(), auth_validation_data);
        assert!(prev.is_none());
    }

    // Finishing the authorization for another state won't work.
    let res = oauth
        .finish_authorization(AuthorizationCode {
            code: "1337".to_owned(),
            state: CsrfToken::new("none".to_owned()),
        })
        .await;

    assert_matches!(
        res,
        Err(OAuthError::AuthorizationCode(OAuthAuthorizationCodeError::InvalidState))
    );
    assert!(client.session_tokens().is_none());
    assert!(oauth.data().unwrap().authorization_data.lock().await.get(&state).is_some());

    // Finishing the authorization for the expected state will work.
    oauth
        .finish_authorization(AuthorizationCode { code: "1337".to_owned(), state: state.clone() })
        .await?;

    assert!(client.session_tokens().is_some());
    assert!(oauth.data().unwrap().authorization_data.lock().await.get(&state).is_none());

    Ok(())
}

#[async_test]
async fn test_oauth_session() -> anyhow::Result<()> {
    let client = MockClientBuilder::new("https://example.org".to_owned()).unlogged().build().await;
    let oauth = client.oauth();

    let tokens = mock_session_tokens_with_refresh();
    let issuer = "https://oauth.example.com/issuer";
    let session = mock_session(tokens.clone(), issuer);
    oauth.restore_session(session.clone()).await?;

    // Test a few extra getters.
    assert_eq!(client.session_tokens().unwrap(), tokens);

    let user_session = oauth.user_session().unwrap();
    assert_eq!(user_session.meta, session.user.meta);
    assert_eq!(user_session.tokens, tokens);
    assert_eq!(user_session.issuer.as_str(), issuer);

    let full_session = oauth.full_session().unwrap();

    assert_eq!(full_session.client_id.as_str(), "test_client_id");
    assert_eq!(full_session.user.meta, session.user.meta);
    assert_eq!(full_session.user.tokens, tokens);
    assert_eq!(full_session.user.issuer.as_str(), issuer);

    Ok(())
}

#[async_test]
async fn test_insecure_clients() -> anyhow::Result<()> {
    let server = MatrixMockServer::new().await;
    let server_url = server.server().uri();

    server.mock_well_known().ok().expect(1).named("well_known").mount().await;
    server.mock_versions().ok().expect(1..).named("versions").mount().await;

    let oauth_server = server.oauth();
    oauth_server.mock_server_metadata().ok().expect(2..).named("server_metadata").mount().await;
    oauth_server.mock_token().ok().expect(2).named("token").mount().await;

    let prev_tokens = mock_prev_session_tokens_with_refresh();
    let next_tokens = mock_session_tokens_with_refresh();

    for client in [
        // Create an insecure client with the homeserver_url method.
        Client::builder().homeserver_url(&server_url).build().await?,
        // Create an insecure client with the insecure_server_name_no_tls method.
        Client::builder()
            .insecure_server_name_no_tls(&ServerName::parse(
                server_url.strip_prefix("http://").unwrap(),
            )?)
            .build()
            .await?,
    ] {
        let oauth = client.oauth();

        // Restore the previous session so we have an existing set of refresh tokens.
        oauth.restore_session(mock_session(prev_tokens.clone(), &server_url)).await?;

        let mut session_changes = client.subscribe_to_session_changes();

        // A refresh in insecure mode should work Just Fine.
        oauth.refresh_access_token().await?;

        assert_eq!(client.session_tokens().unwrap(), next_tokens);

        // We get notified once that the tokens were refreshed.
        assert_eq!(
            session_changes.try_recv(),
            Ok(SessionChange::TokensRefreshed),
            "The session changes should be notified of the tokens refresh"
        );
        assert_eq!(
            session_changes.try_recv(),
            Err(TryRecvError::Empty),
            "There should be no more session changes"
        );
    }

    Ok(())
}

#[async_test]
async fn test_register_client() {
    let server = MatrixMockServer::new().await;
    let oauth_server = server.oauth();
    let client = server.client_builder().unlogged().build().await;
    let oauth = client.oauth();
    let client_metadata = mock_client_metadata();

    // Server doesn't support registration, it fails.
    oauth_server
        .mock_server_metadata()
        .ok_without_registration()
        .expect(1)
        .named("metadata_without_registration")
        .mount()
        .await;

    let result = oauth.register_client(&client_metadata).await;
    assert_matches!(
        result,
        Err(OAuthError::ClientRegistration(OAuthClientRegistrationError::NotSupported))
    );

    server.verify_and_reset().await;

    // Server supports registration, it succeeds.
    oauth_server
        .mock_server_metadata()
        .ok()
        .expect(1)
        .named("metadata_with_registration")
        .mount()
        .await;
    oauth_server.mock_registration().ok().expect(1).named("registration").mount().await;

    let response = oauth.register_client(&client_metadata).await.unwrap();
    assert_eq!(response.client_id.as_str(), "test_client_id");

    let auth_data = oauth.data().unwrap();
    // There is a difference of ending slash between the strings so we parse them
    // with `Url` which will normalize that.
    assert_eq!(auth_data.issuer, Url::parse(&server.server().uri()).unwrap());
    assert_eq!(auth_data.client_id, response.client_id);
}

#[async_test]
async fn test_management_url_cache() {
    let server = MatrixMockServer::new().await;

    let oauth_server = server.oauth();
    oauth_server.mock_server_metadata().ok().expect(1).mount().await;

    let client = server.client_builder().logged_in_with_oauth(server.server().uri()).build().await;
    let oauth = client.oauth();

    // The cache should not contain the entry.
    assert!(!client.inner.caches.server_metadata.lock().await.contains("SERVER_METADATA"));

    let management_url = oauth
        .account_management_url(Some(AccountManagementActionFull::Profile))
        .await
        .expect("We should be able to fetch the account management url");

    assert!(management_url.is_some());

    // Check that the server metadata has been inserted into the cache.
    assert!(client.inner.caches.server_metadata.lock().await.contains("SERVER_METADATA"));

    // Another parameter doesn't make another request for the metadata.
    let management_url = oauth
        .account_management_url(Some(AccountManagementActionFull::SessionsList))
        .await
        .expect("We should be able to fetch the account management url");

    assert!(management_url.is_some());
}

#[async_test]
async fn test_server_metadata() {
    let server = MatrixMockServer::new().await;
    let client = server.client_builder().unlogged().build().await;
    let oauth = client.oauth();
    let issuer = server.server().uri();

    // The endpoint is not mocked so it is not supported.
    let error = oauth.server_metadata().await.unwrap_err();
    assert!(error.is_not_supported());

    // Mock the `GET /auth_issuer` fallback endpoint.
    Mock::given(method("GET"))
        .and(path("/_matrix/client/unstable/org.matrix.msc2965/auth_issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issuer": issuer})))
        .expect(1)
        .named("auth_issuer")
        .mount(server.server())
        .await;
    let metadata = MockServerMetadataBuilder::new(&issuer).build();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .expect(1)
        .named("openid-configuration")
        .mount(server.server())
        .await;
    oauth.server_metadata().await.unwrap();

    // Mock the `GET /auth_metadata` endpoint.
    let oauth_server = server.oauth();
    oauth_server.mock_server_metadata().ok().expect(1).named("auth_metadata").mount().await;

    oauth.server_metadata().await.unwrap();
}
