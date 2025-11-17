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

use matrix_sdk_base::crypto::types::qr_login::{QrCodeData, QrCodeIntent};
use serde::{Serialize, de::DeserializeOwned};
use tracing::{instrument, trace};
use url::Url;
use vodozemac::ecies::{
    CheckCode, Ecies, EstablishedEcies, InboundCreationResult, InitialMessage, Message,
    OutboundCreationResult,
};

use super::{
    SecureChannelError as Error,
    rendezvous_channel::{InboundChannelCreationResult, RendezvousChannel},
};
use crate::{config::RequestConfig, http_client::HttpClient};

const LOGIN_INITIATE_MESSAGE: &str = "MATRIX_QR_CODE_LOGIN_INITIATE";
const LOGIN_OK_MESSAGE: &str = "MATRIX_QR_CODE_LOGIN_OK";

pub(super) struct SecureChannel {
    channel: RendezvousChannel,
    qr_code_data: QrCodeData,
    ecies: Ecies,
}

impl SecureChannel {
    /// Create a new secure channel to request a login with.
    pub(super) async fn login(
        http_client: HttpClient,
        homeserver_url: &Url,
    ) -> Result<Self, Error> {
        let channel = RendezvousChannel::create_outbound(http_client, homeserver_url).await?;
        let rendezvous_id = channel.rendezvous_id().to_owned();
        let intent = QrCodeIntent::Login;

        let ecies = Ecies::new();
        let public_key = ecies.public_key();

        let qr_code_data =
            QrCodeData { intent, public_key, rendezvous_id, base_url: homeserver_url.to_owned() };

        Ok(Self { channel, qr_code_data, ecies })
    }

    /// Create a new secure channel to reciprocate an existing login with.
    pub(super) async fn reciprocate(
        http_client: HttpClient,
        homeserver_url: &Url,
    ) -> Result<Self, Error> {
        let mut channel = SecureChannel::login(http_client, homeserver_url).await?;
        channel.qr_code_data.base_url = homeserver_url.clone();
        channel.qr_code_data.intent = QrCodeIntent::Reciprocate;
        Ok(channel)
    }

    pub(super) fn qr_code_data(&self) -> &QrCodeData {
        &self.qr_code_data
    }

    #[instrument(skip(self))]
    pub(super) async fn connect(mut self) -> Result<AlmostEstablishedSecureChannel, Error> {
        trace!("Trying to connect the secure channel.");

        let message = self.channel.receive().await?;
        let message = InitialMessage::decode(&message)?;

        let InboundCreationResult { ecies, message } =
            self.ecies.establish_inbound_channel(&message)?;
        let message = std::str::from_utf8(&message)?;

        trace!("Received the initial secure channel message");

        if message == LOGIN_INITIATE_MESSAGE {
            let mut secure_channel = EstablishedSecureChannel { channel: self.channel, ecies };

            trace!("Sending the LOGIN OK message");

            secure_channel.send(LOGIN_OK_MESSAGE).await?;

            Ok(AlmostEstablishedSecureChannel { secure_channel })
        } else {
            Err(Error::SecureChannelMessage {
                expected: LOGIN_INITIATE_MESSAGE,
                received: message.to_owned(),
            })
        }
    }
}

/// An SecureChannel that is yet to be confirmed as with the [`CheckCode`].
/// Same deal as for the [`SecureChannel`], not used for now.
pub(super) struct AlmostEstablishedSecureChannel {
    secure_channel: EstablishedSecureChannel,
}

impl AlmostEstablishedSecureChannel {
    /// Confirm that the secure channel is indeed secure.
    ///
    /// The check code needs to be received out of band from the other side of
    /// the secure channel.
    pub(super) fn confirm(self, check_code: u8) -> Result<EstablishedSecureChannel, Error> {
        if check_code == self.secure_channel.check_code().to_digit() {
            Ok(self.secure_channel)
        } else {
            Err(Error::InvalidCheckCode)
        }
    }
}

pub(super) struct EstablishedSecureChannel {
    channel: RendezvousChannel,
    ecies: EstablishedEcies,
}

impl EstablishedSecureChannel {
    /// Establish a secure channel from a scanned QR code.
    #[instrument(skip(client))]
    pub(super) async fn from_qr_code(
        client: reqwest::Client,
        qr_code_data: &QrCodeData,
        our_intent: QrCodeIntent,
    ) -> Result<Self, Error> {
        if qr_code_data.intent == our_intent {
            println!(
                "QR code intent {:?} matches our intent {:?}",
                qr_code_data.intent, our_intent
            );
            Err(Error::InvalidIntent)
        } else {
            trace!("Attempting to create a new inbound secure channel from a QR code.");

            let client = HttpClient::new(client, RequestConfig::short_retry());
            let ecies = Ecies::new();

            // Let's establish an outbound ECIES channel, the other side won't know that
            // it's talking to us, the device that scanned the QR code, until it
            // receives and successfully decrypts the initial message. We're here encrypting
            // the `LOGIN_INITIATE_MESSAGE`.
            let OutboundCreationResult { ecies, message } = ecies.establish_outbound_channel(
                qr_code_data.public_key,
                LOGIN_INITIATE_MESSAGE.as_bytes(),
            )?;

            // The other side has crated a rendezvous channel, we're going to connect to it
            // and send this initial encrypted message through it. The initial message on
            // the rendezvous channel will have an empty body, so we can just
            // drop it.
            let InboundChannelCreationResult { mut channel, .. } =
                RendezvousChannel::create_inbound(
                    client,
                    &qr_code_data.base_url,
                    &qr_code_data.rendezvous_id,
                )
                .await?;

            trace!(
                "Received the initial message from the rendezvous channel, sending the LOGIN \
                 INITIATE message"
            );

            // Now we're sending the encrypted message through the rendezvous channel to the
            // other side.
            let encoded_message = message.encode();
            channel.send(encoded_message).await?;

            trace!("Waiting for the LOGIN OK message");

            // We can create our EstablishedSecureChannel struct now and use the
            // convenient helpers which transparently decrypt on receival.
            let mut ret = Self { channel, ecies };
            let response = ret.receive().await?;

            trace!("Received the LOGIN OK message, maybe.");

            if response == LOGIN_OK_MESSAGE {
                Ok(ret)
            } else {
                Err(Error::SecureChannelMessage { expected: LOGIN_OK_MESSAGE, received: response })
            }
        }
    }

    /// Get the [`CheckCode`] which can be used to, out of band, verify that
    /// both sides of the channel are indeed communicating with each other and
    /// not with a 3rd party.
    pub(super) fn check_code(&self) -> &CheckCode {
        self.ecies.check_code()
    }

    /// Send the given message over to the other side.
    ///
    /// The message will be encrypted before it is sent over the rendezvous
    /// channel.
    pub(super) async fn send_json(&mut self, message: impl Serialize) -> Result<(), Error> {
        let message = serde_json::to_string(&message)?;
        self.send(&message).await
    }

    /// Attempt to receive a message from the channel.
    ///
    /// The message will be decrypted after it has been received over the
    /// rendezvous channel.
    pub(super) async fn receive_json<D: DeserializeOwned>(&mut self) -> Result<D, Error> {
        let message = self.receive().await?;
        Ok(serde_json::from_str(&message)?)
    }

    async fn send(&mut self, message: &str) -> Result<(), Error> {
        let message = self.ecies.encrypt(message.as_bytes());
        let message = message.encode();

        Ok(self.channel.send(message).await?)
    }

    async fn receive(&mut self) -> Result<String, Error> {
        let ciphertext = self.channel.receive().await?;
        let message = Message::decode(&ciphertext)?;

        let decrypted = self.ecies.decrypt(&message)?;

        Ok(String::from_utf8(decrypted).map_err(|e| e.utf8_error())?)
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
pub(super) mod test {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    };

    use matrix_sdk_base::crypto::types::qr_login::QrCodeIntent;
    use matrix_sdk_common::executor::spawn;
    use matrix_sdk_test::async_test;
    use serde_json::json;
    use similar_asserts::assert_eq;
    use url::Url;
    use wiremock::{
        Mock, MockGuard, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{EstablishedSecureChannel, SecureChannel};
    use crate::http_client::HttpClient;

    #[allow(dead_code)]
    pub struct MockedRendezvousServer {
        pub base_url: Url,
        pub rendezvous_id: String,
        data: Arc<Mutex<String>>,
        sequence_token: Arc<AtomicU32>,
        post_guard: MockGuard,
        put_guard: MockGuard,
        get_guard: MockGuard,
    }

    const BASE_PATH: &str = "/_matrix/client/unstable/io.element.msc4108/rendezvous";

    impl MockedRendezvousServer {
        pub async fn new(server: &MockServer, rendezvous_id: &str) -> Self {
            let data: Arc<Mutex<String>> = Mutex::new("".to_owned()).into();
            let sequence_token = Arc::new(AtomicU32::new(0));

            let base_url = Url::parse(&server.uri())
                .expect("We should be able to parse the example homeserver");

            let post_guard = server
                .register_as_scoped(Mock::given(method("POST")).and(path(BASE_PATH)).respond_with(
                    {
                        let data = data.clone();
                        let sequence_token = sequence_token.clone();
                        let rendezvous_id = rendezvous_id.to_owned();

                        move |request: &wiremock::Request| {
                            // parse the JSON request body
                            let body: serde_json::Value =
                                serde_json::from_slice(&request.body).unwrap();

                            // store the new data in the Mutex
                            let new_data = body.get("data").unwrap().to_string();
                            *data.lock().unwrap() = new_data;

                            // increment the sequence token
                            sequence_token.fetch_add(1, Ordering::SeqCst);

                            ResponseTemplate::new(200).set_body_json(json!({
                                "id": rendezvous_id,
                                "sequence_token": sequence_token.load(Ordering::SeqCst).to_string(),
                                "expires_ts": 1662560931000_u64,
                            }))
                        }
                    },
                ))
                .await;

            let put_guard = server
                .register_as_scoped(
                    Mock::given(method("PUT")).and(path(format!("{BASE_PATH}/{rendezvous_id}"))).respond_with({
                        let data = data.clone();
                        let sequence_token = sequence_token.clone();

                        move |request: &wiremock::Request| {
                            // parse the JSON request body                        
                            let body: serde_json::Value =
                                serde_json::from_slice(&request.body).unwrap();

                            // check that the sequence token matches
                            let expected_sequence_token =
                                body.get("sequence_token").unwrap().as_str().unwrap();

                            let current_sequence_token: String =
                                sequence_token.load(Ordering::SeqCst).to_string();
                            if expected_sequence_token != current_sequence_token {
                                return ResponseTemplate::new(409).set_body_json(json!({
                                    "errcode": "IO_ELEMENT_MSC4108_CONCURRENT_WRITE",
                                    "error": format!("Invalid sequence token: expected {}, got {}", current_sequence_token, expected_sequence_token),
                                }));
                            }

                            // store the new data in the Mutex
                            let new_data = body.get("data").unwrap().as_str().unwrap().to_owned();
                            *data.lock().unwrap() = new_data;

                            // increment the sequence token
                            sequence_token.fetch_add(1, Ordering::SeqCst);

                            ResponseTemplate::new(200).set_body_json(json!({
                                "sequence_token": sequence_token.load(Ordering::SeqCst).to_string()
                            }))
                        }
                    }),
                )
                .await;

            let get_guard = server
                .register_as_scoped(
                    Mock::given(method("GET"))
                        .and(path(format!("{BASE_PATH}/{rendezvous_id}")))
                        .respond_with({
                            let data = data.clone();
                            let sequence_token = sequence_token.clone();

                            move |_request: &wiremock::Request| {
                                if sequence_token.load(Ordering::SeqCst) == 0 {
                                    // no POST yet, return 404
                                    return ResponseTemplate::new(404).set_body_json(json!({
                                        "errcode": "M_NOT_FOUND",
                                        "error": "The rendezvous hasn't been created yet."
                                    }));
                                }

                                ResponseTemplate::new(200).set_body_json(json!({
                                "data": data.clone().lock().unwrap().to_string(),
                                "sequence_token": sequence_token.load(Ordering::SeqCst).to_string(),
                            }))
                            }
                        }),
                )
                .await;

            Self {
                data,
                sequence_token,
                post_guard,
                put_guard,
                get_guard,
                base_url,
                rendezvous_id: rendezvous_id.to_owned(),
            }
        }
    }

    #[async_test]
    async fn test_creation() {
        let server = MockServer::start().await;
        let rendezvous_server = MockedRendezvousServer::new(&server, "abcdEFG12345").await;

        let client = HttpClient::new(reqwest::Client::new(), Default::default());
        let alice = SecureChannel::reciprocate(client, &rendezvous_server.base_url)
            .await
            .expect("Alice should be able to create a secure channel.");

        let qr_code_data = alice.qr_code_data().clone();

        let bob_task = spawn(async move {
            EstablishedSecureChannel::from_qr_code(
                reqwest::Client::new(),
                &qr_code_data,
                QrCodeIntent::Login,
            )
            .await
            .expect("Bob should be able to fully establish the secure channel.")
        });

        let alice_task = spawn(async move {
            alice
                .connect()
                .await
                .expect("Alice should be able to connect the established secure channel")
        });

        let bob = bob_task.await.unwrap();
        let alice = alice_task.await.unwrap();

        assert_eq!(alice.secure_channel.check_code(), bob.check_code());

        let alice = alice
            .confirm(bob.check_code().to_digit())
            .expect("Alice should be able to confirm the established secure channel.");

        assert_eq!(bob.channel.rendezvous_id(), alice.channel.rendezvous_id());
    }
}
