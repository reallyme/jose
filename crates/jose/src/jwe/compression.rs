// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;
use std::io::{self, BufRead, Cursor, Read, Write};
use std::rc::Rc;

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
const DEFLATE_INPUT_CHUNK_BYTES: usize = 1024;
const MAX_DEFLATE_INPUT_EXCESS_BYTES: usize = 16 * 1024;
const DEFLATE_OUTPUT_CHUNK_BYTES: usize = 8192;
const INITIAL_DEFLATE_OUTPUT_CAPACITY: usize = 4096;

// flate2 can process arbitrarily many empty DEFLATE blocks before returning
// output from a single read. Meter its input while decoding so a valid-tag JWE
// cannot spend unbounded CPU on a stream with little or no plaintext.
struct MeteredDeflateInput<'a> {
    inner: Cursor<&'a [u8]>,
    produced: Rc<Cell<usize>>,
}

impl Read for MeteredDeflateInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let read = {
            let available = self.fill_buf()?;
            let read = available.len().min(output.len());
            output
                .get_mut(..read)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
                .copy_from_slice(
                    available
                        .get(..read)
                        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?,
                );
            read
        };
        self.consume(read);
        Ok(read)
    }
}

impl BufRead for MeteredDeflateInput<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let consumed = usize::try_from(self.inner.position())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let allowed = self
            .produced
            .get()
            .checked_add(MAX_DEFLATE_INPUT_EXCESS_BYTES)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let available = self.inner.fill_buf()?;
        if available.is_empty() {
            return Ok(available);
        }
        let remaining = allowed
            .checked_sub(consumed)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if remaining == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let exposed = available
            .len()
            .min(DEFLATE_INPUT_CHUNK_BYTES)
            .min(remaining);
        available
            .get(..exposed)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }
}

fn append_plaintext(plaintext: &mut Zeroizing<Vec<u8>>, chunk: &[u8]) -> Result<(), JweError> {
    let next_len = plaintext
        .len()
        .checked_add(chunk.len())
        .ok_or(JweError::LengthOverflow)?;
    if next_len > MAX_DECOMPRESSED_JWE_BYTES {
        return Err(JweError::DecompressedPlaintextTooLarge);
    }
    if next_len > plaintext.capacity() {
        // Vec::reserve may free an old plaintext-bearing allocation without
        // wiping it. Move through a new owner and zeroize the old one first.
        let next_capacity = plaintext
            .capacity()
            .max(INITIAL_DEFLATE_OUTPUT_CAPACITY)
            .checked_mul(2)
            .ok_or(JweError::LengthOverflow)?
            .max(next_len)
            .min(MAX_DECOMPRESSED_JWE_BYTES);
        let mut replacement = Zeroizing::new(Vec::new());
        replacement
            .try_reserve_exact(next_capacity)
            .map_err(|_| JweError::Decompression)?;
        replacement.extend_from_slice(plaintext);
        core::mem::swap(&mut **plaintext, &mut *replacement);
    }
    plaintext.extend_from_slice(chunk);
    Ok(())
}

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
        let next_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if next_len > MAX_DECOMPRESSED_JWE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if next_len > self.bytes.capacity() {
            let next_capacity = self
                .bytes
                .capacity()
                .max(INITIAL_DEFLATE_OUTPUT_CAPACITY)
                .checked_mul(2)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
                .max(next_len)
                .min(MAX_DECOMPRESSED_JWE_BYTES);
            let mut replacement = Zeroizing::new(Vec::new());
            replacement
                .try_reserve_exact(next_capacity)
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            replacement.extend_from_slice(&self.bytes);
            core::mem::swap(&mut *self.bytes, &mut *replacement);
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
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
    let produced = Rc::new(Cell::new(0));
    let input = MeteredDeflateInput {
        inner: Cursor::new(compressed),
        produced: Rc::clone(&produced),
    };
    let mut decoder = DeflateDecoder::new(input);
    let mut plaintext = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; DEFLATE_OUTPUT_CHUNK_BYTES]);
    loop {
        let read = decoder
            .read(&mut *chunk)
            .map_err(|_| JweError::Decompression)?;
        if read == 0 {
            break;
        }
        let emitted = chunk.get(..read).ok_or(JweError::Decompression)?;
        append_plaintext(&mut plaintext, emitted)?;
        produced.set(plaintext.len());
    }

    let consumed = usize::try_from(decoder.into_inner().inner.position())
        .map_err(|_| JweError::LengthOverflow)?;
    if consumed != compressed.len() {
        return Err(JweError::Decompression);
    }

    Ok(plaintext)
}
