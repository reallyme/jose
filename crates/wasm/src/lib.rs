// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! npm-facing WebAssembly boundary for ReallyMe JOSE.

#![forbid(unsafe_code)]

mod operation;

pub use operation::{execute_operation, execute_operation_json};
