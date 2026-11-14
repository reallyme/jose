// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::mem::ManuallyDrop;

use buffa::encoding::{decode_unknown_field, Tag, WireType, MAX_FIELD_NUMBER};
use buffa::{DecodeContext, DecodeError};

use super::{JOSE_PROTO_RECURSION_LIMIT, JOSE_PROTO_UNKNOWN_FIELD_LIMIT};

#[kani::proof]
#[kani::unwind(2)]
fn unknown_operation_fields_cannot_pass_the_production_decode_budget() {
    let field = kani::any::<u32>();
    kani::assume((1..=MAX_FIELD_NUMBER).contains(&field));
    // Executable oneof alternatives contain messages (length-delimited fields).
    // The generated envelopes route unrecognized tags to this decoder.
    let tag = Tag::new(field, WireType::LengthDelimited);
    let limit = Cell::new(JOSE_PROTO_UNKNOWN_FIELD_LIMIT);
    let context = DecodeContext::new(JOSE_PROTO_RECURSION_LIMIT, &limit);
    let bytes = kani::any::<[u8; 1]>();
    let mut input = bytes.as_slice();
    let result = ManuallyDrop::new(decode_unknown_field(tag, &mut input, context));

    kani::assert(
        matches!(*result, Err(DecodeError::UnknownFieldLimitExceeded)),
        "no unknown selector can pass the executable envelope's decode budget",
    );
    kani::assert(
        input == bytes.as_slice(),
        "reject before reading the unknown field",
    );
    kani::cover!(
        field == 3999 && result.is_err(),
        "unknown operation in the JWE field range"
    );
}
