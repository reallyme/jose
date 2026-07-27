# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

-keep class me.really.jose.ReallyMeJoseNative { *; }
-keep class me.really.jose.ReallyMeJoseException { *; }
-keep class me.really.jose.ReallyMeJoseException$* { *; }

# Protobuf Lite reflects on generated backing fields from encoded schema
# metadata. Renaming these classes or members breaks request/response parsing.
-keep class me.really.jose.v1.** { *; }
