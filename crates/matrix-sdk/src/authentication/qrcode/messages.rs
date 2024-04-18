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

use matrix_sdk_base::crypto::types::SecretsBundle;
use openidconnect::{
    core::CoreDeviceAuthorizationResponse, EndUserVerificationUrl, VerificationUriComplete,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;
use vodozemac::Curve25519PublicKey;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum QrAuthMessage {
    #[serde(rename = "m.login.protocols")]
    LoginProtocols { protocols: Vec<String>, homeserver: Url },
    #[serde(rename = "m.login.protocol")]
    LoginProtocol {
        device_authorization_grant: AuthorizationGrant,
        // TODO: This should be an enum.
        protocol: String,
        #[serde(
            deserialize_with = "deserialize_curve_key",
            serialize_with = "serialize_curve_key"
        )]
        device_id: Curve25519PublicKey,
    },
    #[serde(rename = "m.login.protocol_accepted")]
    LoginProtocolAccepted {},
    #[serde(rename = "m.login.success")]
    LoginSuccess {},
    #[serde(rename = "m.login.declined")]
    LoginDeclined {},
    #[serde(rename = "m.login.secrets")]
    LoginSecrets(SecretsBundle),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationGrant {
    pub verification_uri: EndUserVerificationUrl,
    pub verification_uri_complete: Option<VerificationUriComplete>,
}

impl QrAuthMessage {
    pub fn login_protocols(
        device_authorization_grant: AuthorizationGrant,
        device_id: Curve25519PublicKey,
    ) -> QrAuthMessage {
        QrAuthMessage::LoginProtocol {
            device_id,
            device_authorization_grant,
            protocol: "device_authorization_grant".to_owned(),
        }
    }
}

impl From<&CoreDeviceAuthorizationResponse> for AuthorizationGrant {
    fn from(value: &CoreDeviceAuthorizationResponse) -> Self {
        Self {
            verification_uri: value.verification_uri().clone(),
            verification_uri_complete: value.verification_uri_complete().cloned(),
        }
    }
}

// Vodozemac serializes Curve25519 keys directly as a byteslice, while Matrix
// likes to base64 encode all byte slices.
//
// This ensures that we serialize/deserialize in a Matrix-compatible way.
pub(crate) fn deserialize_curve_key<'de, D>(de: D) -> Result<Curve25519PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let key: String = Deserialize::deserialize(de)?;
    Curve25519PublicKey::from_base64(&key).map_err(serde::de::Error::custom)
}

pub(crate) fn serialize_curve_key<S>(key: &Curve25519PublicKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let key = key.to_base64();
    s.serialize_str(&key)
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use serde_json::json;

    use super::*;

    #[test]
    fn deserialize() {
        let json = json!({
            "type": "m.login.protocols",
            "protocols": ["device_authorization_grant"],
            "homeserver": "https://matrix-client.matrix.org"

        });

        let message: QrAuthMessage = serde_json::from_value(json).unwrap();

        assert_matches!(message, QrAuthMessage::LoginProtocols { .. });
    }
}
