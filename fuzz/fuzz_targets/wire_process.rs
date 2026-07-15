// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz the process-proto and JSON wire dispatch boundaries.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_crypto::core::{CryptoError, RngOutputKind};
use reallyme_crypto::csprng::SecureRandom;
use reallyme_jose::wire::{process_json, process_proto};

struct FuzzRandom {
    seed: u8,
}

impl SecureRandom for FuzzRandom {
    fn fill_secure(
        &mut self,
        output: &mut [u8],
        _output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        for (index, byte) in output.iter_mut().enumerate() {
            let offset = match u8::try_from(index % 251) {
                Ok(value) => value,
                Err(_) => return Err(CryptoError::InvalidKey),
            };
            *byte = self.seed.wrapping_add(offset);
        }
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let mut rng = FuzzRandom { seed: selector };
    if selector & 1 == 0 {
        let _ = process_proto(body, &mut rng);
    } else {
        let _ = process_json(body, &mut rng);
    }
});
