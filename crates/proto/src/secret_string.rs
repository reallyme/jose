// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! UTF-8 field ownership used by the generated cleanup profile.

use buffa::{bytes::Buf, DecodeError, FieldPayload, ProtoString, WirePayload};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Wipe-owned UTF-8 protobuf text, including spare allocation capacity.
///
/// Clone is required by the protobuf runtime; each copy owns its cleanup.
/// JSON export remains permitted by the existing JOSE operation contract.
pub struct SecretString(SecretBox<String>);
impl SecretString {
    /// Borrows text without copying its storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    /// Transfers storage to an existing zeroizing domain owner.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(core::mem::take(self.0.expose_secret_mut()))
    }
}
impl Default for SecretString {
    fn default() -> Self {
        String::new().into()
    }
}
impl Clone for SecretString {
    fn clone(&self) -> Self {
        self.as_str().to_owned().into()
    }
}
impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}
impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}
impl core::ops::Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}
impl<T: AsRef<str> + ?Sized> PartialEq<T> for SecretString {
    fn eq(&self, other: &T) -> bool {
        bool::from(self.as_bytes().ct_eq(other.as_ref().as_bytes()))
    }
}
impl Eq for SecretString {}
impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretString {}
impl ProtoString for SecretString {
    fn from_wire(payload: WirePayload<'_>) -> Result<Self, DecodeError> {
        payload.to_str().map(Into::into)
    }
    fn decode_length_delimited(payload: &mut FieldPayload<impl Buf>) -> Result<Self, DecodeError> {
        let mut bytes = crate::guarded_decode::read(payload)?;
        core::str::from_utf8(&bytes).map_err(|_| DecodeError::InvalidUtf8)?;
        match String::from_utf8(core::mem::take(&mut *bytes)) {
            Ok(text) => Ok(text.into()),
            Err(error) => {
                let mut rejected = Zeroizing::new(error.into_bytes());
                rejected.zeroize();
                Err(DecodeError::InvalidUtf8)
            }
        }
    }
}
impl buffa::json_helpers::ProtoStringJson for SecretString {
    fn serialize_json<S: serde::Serializer>(text: &str, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(text)
    }
    fn deserialize_json<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct Text;
        impl serde::de::Visitor<'_> for Text {
            type Value = SecretString;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(value.into())
            }
        }
        deserializer.deserialize_string(Text)
    }
}
