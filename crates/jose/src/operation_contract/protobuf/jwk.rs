// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{JoseJwkThumbprintSha256Request, JoseJwkThumbprintSha256Result};
use crate::jwk::{thumbprint_sha256, JwkThumbprintMembers};
use crate::wire::JoseWireResult;

pub(crate) fn thumbprint(
    request: &JoseJwkThumbprintSha256Request,
) -> JoseWireResult<JoseJwkThumbprintSha256Result> {
    let members = JwkThumbprintMembers::try_from(request)
        .map_err(|error| crate::map_failure::jwk_thumbprint(&error))?;
    let digest =
        thumbprint_sha256(&members).map_err(|error| crate::map_failure::jwk_thumbprint(&error))?;
    Ok(JoseJwkThumbprintSha256Result {
        digest: digest.to_vec().into(),
    })
}
