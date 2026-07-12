<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# JOSE Conformance

This directory records the conformance surface for `reallyme-jose`.

Requirement records name the normative source section, the implementation files
that enforce it, and the positive and negative tests that cover it. Vector
files are portable fixtures used by local Rust tests and by SDKs that need
byte-for-byte JOSE parity.

The vector manifest in [vectors/manifest.json](vectors/manifest.json) is audited
by the standalone `tools/vector-audit` crate. The audit tool avoids linking the
production JOSE, codec, and crypto crates so committed fixtures are checked by
an independent implementation path.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) and
[NOTICE](../NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
