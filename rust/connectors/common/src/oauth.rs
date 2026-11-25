// SPDX-License-Identifier: Apache-2.0
//! OAuth 2.0 client credentials grant (RFC 6749 4.4): a bearer token fetched from the token
//! endpoint with the client id and secret in the form body, and reused until shortly before it
//! expires.

use std::time::{Duration, Instant};

use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use serde::Deserialize;

/// A token is fetched again this long before the server says it expires.
const REFRESH_MARGIN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClient {
    pub token_url: String,
    pub client_id: String,
    pub client_secret_file: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("reading client secret {path}: {source}")]
    Secret {
        path: String,
        source: std::io::Error,
    },
    #[error("client secret file {0} is empty")]
    EmptySecret(String),
    #[error("token request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("token endpoint answered {0}")]
    Status(StatusCode),
    #[error("access token is not a valid header value")]
    InvalidToken,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

struct Token {
    authorization: HeaderValue,
    /// `None` when the server gave no lifetime.
    refresh_at: Option<Instant>,
}

/// Holds the client's credentials and its current token.
pub struct TokenSource {
    http: reqwest::Client,
    client: OAuthClient,
    secret: String,
    token: Option<Token>,
}

impl TokenSource {
    /// Reads the client secret. No request is made until the first [`Self::authorization`].
    pub fn new(http: reqwest::Client, client: OAuthClient) -> Result<Self, OAuthError> {
        let secret = std::fs::read_to_string(&client.client_secret_file)
            .map_err(|source| OAuthError::Secret {
                path: client.client_secret_file.clone(),
                source,
            })?
            .trim()
            .to_string();
        if secret.is_empty() {
            return Err(OAuthError::EmptySecret(client.client_secret_file));
        }
        Ok(TokenSource {
            http,
            client,
            secret,
            token: None,
        })
    }

    /// The `Authorization` header value, fetching a token when none is held or the held one is
    /// about to expire.
    pub async fn authorization(&mut self) -> Result<HeaderValue, OAuthError> {
        let now = Instant::now();
        if let Some(token) = &self.token {
            if token.refresh_at.is_none_or(|at| now < at) {
                return Ok(token.authorization.clone());
            }
        }
        let token = self.fetch().await?;
        let authorization = token.authorization.clone();
        self.token = Some(token);
        Ok(authorization)
    }

    /// Drops the held token, for a request the server refused with it.
    pub fn invalidate(&mut self) {
        self.token = None;
    }

    async fn fetch(&self) -> Result<Token, OAuthError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.client.client_id.as_str()),
            ("client_secret", self.secret.as_str()),
        ];
        if let Some(scope) = &self.client.scope {
            form.push(("scope", scope.as_str()));
        }
        let requested_at = Instant::now();
        let resp = self
            .http
            .post(&self.client.token_url)
            .form(&form)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(OAuthError::Status(resp.status()));
        }
        let response: TokenResponse = resp.json().await?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", response.access_token))
            .map_err(|_| OAuthError::InvalidToken)?;
        authorization.set_sensitive(true);
        let refresh_at = response
            .expires_in
            .map(|s| requested_at + Duration::from_secs(s).saturating_sub(REFRESH_MARGIN));
        tracing::debug!(token_url = %self.client.token_url, expires_in = ?response.expires_in, "oauth token fetched");
        Ok(Token {
            authorization,
            refresh_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_mock::{secret_file, token_reply, MockServer, Reply};

    fn client(token_url: String, secret: &tempfile::NamedTempFile) -> OAuthClient {
        OAuthClient {
            token_url,
            client_id: "radar-1".into(),
            client_secret_file: secret.path().to_str().unwrap().into(),
            scope: Some("tracks".into()),
        }
    }

    async fn source(server: &MockServer, secret: &tempfile::NamedTempFile) -> TokenSource {
        crate::nats::install_crypto_provider();
        TokenSource::new(reqwest::Client::new(), client(server.url("/token"), secret)).unwrap()
    }

    #[tokio::test]
    async fn sends_client_credentials_in_the_form_body() {
        let server = MockServer::start(vec![token_reply("t1", 300)]).await;
        let secret = secret_file("s3cret\n");
        let auth = source(&server, &secret)
            .await
            .authorization()
            .await
            .unwrap();
        assert_eq!(auth, "Bearer t1");
        let request = server.requests().remove(0);
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.body,
            "grant_type=client_credentials&client_id=radar-1&client_secret=s3cret&scope=tracks"
        );
    }

    #[tokio::test]
    async fn token_is_reused_until_it_nears_expiry() {
        let server = MockServer::start(vec![token_reply("t1", 300)]).await;
        let secret = secret_file("s3cret");
        let mut tokens = source(&server, &secret).await;
        tokens.authorization().await.unwrap();
        tokens.authorization().await.unwrap();
        assert_eq!(server.requests().len(), 1, "second call reused the token");
    }

    #[tokio::test]
    async fn token_inside_the_margin_is_fetched_again() {
        let server = MockServer::start(vec![token_reply("t1", 10), token_reply("t2", 300)]).await;
        let secret = secret_file("s3cret");
        let mut tokens = source(&server, &secret).await;
        tokens.authorization().await.unwrap();
        assert_eq!(tokens.authorization().await.unwrap(), "Bearer t2");
    }

    #[tokio::test]
    async fn invalidated_token_is_fetched_again() {
        let server = MockServer::start(vec![token_reply("t1", 300), token_reply("t2", 300)]).await;
        let secret = secret_file("s3cret");
        let mut tokens = source(&server, &secret).await;
        tokens.authorization().await.unwrap();
        tokens.invalidate();
        assert_eq!(tokens.authorization().await.unwrap(), "Bearer t2");
    }

    #[tokio::test]
    async fn refused_credentials_name_the_status() {
        let server =
            MockServer::start(vec![Reply::json(401, r#"{"error":"invalid_client"}"#)]).await;
        let secret = secret_file("wrong");
        let err = source(&server, &secret)
            .await
            .authorization()
            .await
            .unwrap_err();
        assert!(
            matches!(err, OAuthError::Status(StatusCode::UNAUTHORIZED)),
            "{err}"
        );
    }

    #[test]
    fn empty_secret_file_is_refused() {
        crate::nats::install_crypto_provider();
        let secret = secret_file("  \n");
        let client = client("http://127.0.0.1:1/token".into(), &secret);
        let err = TokenSource::new(reqwest::Client::new(), client)
            .err()
            .unwrap();
        assert!(matches!(err, OAuthError::EmptySecret(_)), "{err}");
    }
}
