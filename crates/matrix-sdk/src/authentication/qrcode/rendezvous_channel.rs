// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use http::{
    header::{CONTENT_TYPE, ETAG, EXPIRES, IF_MATCH, IF_NONE_MATCH, LAST_MODIFIED},
    Method, StatusCode,
};
use url::Url;

use super::requests;
use crate::{http_client::HttpClient, HttpError};

pub type Etag = String;

pub(super) struct RendezvousChannel {
    client: HttpClient,
    rendezvous_url: Url,
    etag: Etag,
}

pub struct InboundChannelCreationResult {
    pub channel: RendezvousChannel,
    pub initial_message: RendezvousMessage,
}

struct RendezvousGetResponse {
    pub status_code: StatusCode,
    pub etag: String,
    pub expires: String,
    pub last_modified: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

pub struct RendezvousMessage {
    pub status_code: StatusCode,
    pub body: Vec<u8>,
    pub content_type: String,
}

impl RendezvousChannel {
    pub(super) async fn create_outbound(
        client: HttpClient,
        rendezvous_server: &Url,
    ) -> Result<Self, HttpError> {
        let request = self::requests::create_rendezvous::Request::new();
        let response = client
            .send(request, None, rendezvous_server.to_string(), None, &[], Default::default())
            .await?;

        let rendezvous_url = response.url;
        let etag = response.etag;

        Ok(Self { client, rendezvous_url, etag })
    }

    pub(super) async fn create_inbound(
        client: HttpClient,
        rendezvous_url: &Url,
    ) -> Result<InboundChannelCreationResult, HttpError> {
        // Receive the initial message, which is empty? But we need the ETAG to fully
        // establish the rendezvous channel.
        let response = Self::receive_data_helper(&client.inner, None, &rendezvous_url).await?;

        let etag = response.etag.clone();

        let initial_message = RendezvousMessage {
            status_code: response.status_code,
            body: response.body,
            content_type: response.content_type.unwrap_or_else(|| "application/octet".to_owned()),
        };

        let channel = Self { client, rendezvous_url: rendezvous_url.clone(), etag };

        Ok(InboundChannelCreationResult { channel, initial_message })
    }

    pub(super) fn rendezvous_url(&self) -> &Url {
        &self.rendezvous_url
    }

    async fn receive_data_helper(
        client: &reqwest::Client,
        etag: Option<String>,
        rendezvous_url: &Url,
    ) -> Result<RendezvousGetResponse, HttpError> {
        let mut builder = client.request(Method::GET, rendezvous_url.to_owned());

        if let Some(etag) = etag {
            builder = builder.header(IF_NONE_MATCH, etag);
        }

        let response = builder.send().await?;

        let status_code = response.status();

        let etag = response.headers().get(ETAG).unwrap().to_str().unwrap().to_owned();
        let expires = response.headers().get(EXPIRES).unwrap().to_str().unwrap().to_owned();
        let last_modified =
            response.headers().get(LAST_MODIFIED).unwrap().to_str().unwrap().to_owned();
        let content_type =
            response.headers().get(CONTENT_TYPE).map(|c| c.to_str().unwrap().to_owned());

        let body = response.bytes().await?.to_vec();

        let response =
            RendezvousGetResponse { status_code, etag, expires, last_modified, content_type, body };

        Ok(response)
    }

    pub(super) async fn receive_data(&mut self) -> Result<RendezvousMessage, HttpError> {
        let etag = Some(self.etag.clone());

        let response =
            Self::receive_data_helper(&self.client.inner, etag, &self.rendezvous_url).await?;

        self.etag = response.etag.clone();

        let message = RendezvousMessage {
            status_code: response.status_code,
            body: response.body,
            content_type: response.content_type.unwrap_or_else(|| "application/octet".to_owned()),
        };

        Ok(message)
    }

    pub(super) async fn send_data(
        &mut self,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), HttpError> {
        let etag = self.etag.clone();

        let mut request = self
            .client
            .inner
            .request(Method::PUT, self.rendezvous_url().to_owned())
            .body(body)
            .header(IF_MATCH, etag);

        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }

        let response = request.send().await?;

        if response.status().is_success() {
            let etag = response.headers().get(ETAG).unwrap().to_str().unwrap().to_owned();
            self.etag = etag;

            Ok(())
        } else {
            todo!()
        }
    }
}
#[cfg(test)]
mod test {
    use matrix_sdk_test::async_test;
    use similar_asserts::assert_eq;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::config::RequestConfig;

    #[async_test]
    async fn creation() {
        let server = MockServer::start().await;

        server
            .register(
                Mock::given(method("POST"))
                    .and(path("/_matrix/client/unstable/org.matrix.msc4108/rendezvous"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .append_header("Location", "abcdEFG12345")
                            .append_header("X-Max-Bytes", "10240")
                            .append_header("ETag", "VmbxF13QDusTgOCt8aoa0d2PQcnBOXeIxEqhw5aQ03o=")
                            .append_header("Expires", "Wed, 07 Sep 2022 14:28:51 GMT")
                            .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT"),
                    ),
            )
            .await;

        let url =
            Url::parse(&server.uri()).expect("We should be able to parse the example homeserver");

        let client = HttpClient::new(reqwest::Client::new(), RequestConfig::short_retry());

        let alice = RendezvousChannel::create_outbound(client, &url)
            .await
            .expect("We should be able to create an outbound rendezvous channel");

        let mut bob = {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path(
                            "/_matrix/client/unstable/org.matrix.msc4108/rendezvous/abcdEFG12345",
                        ))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .append_header("Content-Type", "application/octet-stream")
                                .append_header("ETag", "1")
                                .append_header("Expires", "Wed, 07 Sep 2022 14:28:51 GMT")
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT"),
                        ),
                )
                .await;

            let client = HttpClient::new(reqwest::Client::new(), RequestConfig::short_retry());
            let InboundChannelCreationResult { channel: bob, initial_message: _ } =
                RendezvousChannel::create_inbound(client, &url).await.expect("");

            assert_eq!(alice.rendezvous_url(), bob.rendezvous_url());

            bob
        };

        {
            let _scope = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path(
                            "/_matrix/client/unstable/org.matrix.msc4108/rendezvous/abcdEFG12345",
                        ))
                        .respond_with(
                            ResponseTemplate::new(304)
                                .append_header("ETag", "1")
                                .append_header("Expires", "Wed, 07 Sep 2022 14:28:51 GMT")
                                .append_header("Last-Modified", "Wed, 07 Sep 2022 14:27:51 GMT"),
                        ),
                )
                .await;

            let response = bob.receive_data().await.expect("");
            assert_eq!(response.status_code, StatusCode::NOT_MODIFIED);
        }
    }
}
