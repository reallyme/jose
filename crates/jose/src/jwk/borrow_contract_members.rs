// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    __buffa::oneof::jose_jwk_thumbprint_sha256request::Key, JoseJwkThumbprintSha256Request,
};

use super::{JwkThumbprintErrorReason, JwkThumbprintMembers};

impl<'a> TryFrom<&'a JoseJwkThumbprintSha256Request> for JwkThumbprintMembers<'a> {
    type Error = JwkThumbprintErrorReason;

    fn try_from(request: &'a JoseJwkThumbprintSha256Request) -> Result<Self, Self::Error> {
        match request.key.as_ref() {
            Some(Key::Ec(key)) => Ok(Self::Ec {
                crv: &key.crv,
                x: &key.x,
                y: &key.y,
            }),
            Some(Key::Okp(key)) => Ok(Self::Okp {
                crv: &key.crv,
                x: &key.x,
            }),
            Some(Key::Rsa(key)) => Ok(Self::Rsa {
                e: &key.e,
                n: &key.n,
            }),
            Some(Key::Oct(key)) => Ok(Self::Oct { k: &key.k }),
            None => Err(JwkThumbprintErrorReason::MissingMember),
        }
    }
}
