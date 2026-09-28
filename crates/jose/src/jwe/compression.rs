// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{Cursor, Read, Write};

use flate2::bufread::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::Zeroizing;

use super::JweError;

/// Maximum plaintext size accepted after compact-JWE decompression.
///
/// The authenticated compressed payload is never allowed to allocate an
/// unbounded output buffer. Keeping this limit equal to the compact-input
/// boundary also gives callers one stable resource ceiling in both directions.
pub const MAX_DECOMPRESSED_JWE_BYTES: usize = 1024 * 1024;

const DEFLATE_COMPRESSION_LEVEL: u32 = 6;

struct ZeroizingWriter {
    bytes: Zeroizing<Vec<u8>>,
}

impl ZeroizingWriter {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl Write for ZeroizingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        Write::write(&mut *self.bytes, buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn compress_deflate(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let output = ZeroizingWriter::new();
    let mut encoder = DeflateEncoder::new(output, Compression::new(DEFLATE_COMPRESSION_LEVEL));
    encoder
        .write_all(plaintext)
        .map_err(|_| JweError::Compression)?;
    encoder
        .finish()
        .map(ZeroizingWriter::into_bytes)
        .map_err(|_| JweError::Compression)
}

pub(crate) fn decompress_deflate(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let bounded_size = MAX_DECOMPRESSED_JWE_BYTES
        .checked_add(1)
        .ok_or(JweError::LengthOverflow)?;
    let bounded_size = u64::try_from(bounded_size).map_err(|_| JweError::LengthOverflow)?;
    let cursor = Cursor::new(compressed);
    let mut decoder = DeflateDecoder::new(cursor);
    let mut plaintext = Zeroizing::new(Vec::new());

    {
        let mut bounded = decoder.by_ref().take(bounded_size);
        bounded
            .read_to_end(&mut plaintext)
            .map_err(|_| JweError::Decompression)?;
    }

    if plaintext.len() > MAX_DECOMPRESSED_JWE_BYTES {
        return Err(JweError::DecompressedPlaintextTooLarge);
    }

    let consumed =
        usize::try_from(decoder.into_inner().position()).map_err(|_| JweError::LengthOverflow)?;
    if consumed != compressed.len() {
        return Err(JweError::Decompression);
    }

    Ok(plaintext)
}
