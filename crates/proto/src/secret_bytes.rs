// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte-field ownership used by the generated cleanup profile.

use buffa::{bytes::Buf, DecodeError, FieldPayload, ProtoBytes, WirePayload};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Independently owned protobuf bytes; live bytes and spare capacity wipe on drop.
///
/// Clone is required by the protobuf runtime. Each clone owns its own allocation.
/// JSON export follows the operation contract and uses wipe-owned Base64 scratch.
pub struct SecretBytes(SecretBox<Vec<u8>>);

impl SecretBytes {
    /// Borrows the bytes without allocating or exposing their owner.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Transfers the allocation to a zeroizing transport or domain owner.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(self.0.expose_secret_mut()))
    }
}
impl Default for SecretBytes {
    fn default() -> Self {
        Vec::new().into()
    }
}
impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        self.as_slice().to_vec().into()
    }
}
impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        // Box the Vec header, preserving spare capacity under the wipe owner.
        // Shrinking to a boxed slice could release formerly occupied storage.
        Self(SecretBox::new(Box::new(value)))
    }
}
impl From<&[u8]> for SecretBytes {
    fn from(value: &[u8]) -> Self {
        value.to_vec().into()
    }
}
impl core::ops::Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}
impl<T: AsRef<[u8]> + ?Sized> PartialEq<T> for SecretBytes {
    fn eq(&self, other: &T) -> bool {
        bool::from(self.as_slice().ct_eq(other.as_ref()))
    }
}
impl Eq for SecretBytes {}
impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SecretBytes {}
impl ProtoBytes for SecretBytes {
    fn from_wire(payload: WirePayload<'_>) -> Result<Self, DecodeError> {
        Ok(payload.as_slice().into())
    }
    fn decode_length_delimited(payload: &mut FieldPayload<impl Buf>) -> Result<Self, DecodeError> {
        let mut bytes = crate::guarded_decode::read(payload)?;
        Ok(core::mem::take(&mut *bytes).into())
    }
}
impl buffa::json_helpers::ProtoBytesJson for SecretBytes {
    fn serialize_json<S: serde::Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        crate::secret_json_bytes::serialize(bytes, serializer)
    }
    fn deserialize_json<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        crate::secret_json_bytes::deserialize(deserializer)
            .map(|mut value| core::mem::take(&mut *value).into())
    }
}

impl std::io::Write for SecretBytes {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let current = self.0.expose_secret_mut();
        let needed = current
            .len()
            .checked_add(input.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        if needed > current.capacity() {
            // Vec's ordinary reserve can free an unwiped allocation. Allocate
            // the replacement first, then keep both buffers guarded until the
            // previous capacity has been erased and released.
            let capacity = current
                .capacity()
                .checked_mul(2)
                .unwrap_or(needed)
                .max(needed);
            let mut next = Zeroizing::new(Vec::new());
            next.try_reserve_exact(capacity)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
            next.extend_from_slice(current);
            let previous = core::mem::replace(current, core::mem::take(&mut *next));
            drop(Zeroizing::new(previous));
        }
        current.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
