// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertExactCallCount,
  assertExclusiveCallSites,
  assertForbiddenTokens,
  assertOperationContractArchitecture,
} from "../operation-contract-readiness.mjs";

class PolicyFailure extends Error {}

const fail = (message) => {
  throw new PolicyFailure(message);
};

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

const readRepositoryText = (path) => readFileSync(resolve(REPOSITORY_ROOT, path), "utf8");

const listRepositoryFiles = (path) => {
  const root = resolve(REPOSITORY_ROOT, path);
  const files = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(absolute);
      } else if (entry.isFile()) {
        files.push(relative(REPOSITORY_ROOT, absolute));
      }
    }
  };
  visit(root);
  return files;
};

test("exact call policy accepts one semantic delegation", () => {
  assert.doesNotThrow(() => {
    assertExactCallCount({
      source: "fn adapter() { sign_jws(input); }",
      name: "sign_jws",
      expected: 1,
      label: "adapter.rs",
      fail,
    });
  });
});

test("exact call policy recognizes a generic Rust function declaration", () => {
  assert.doesNotThrow(() => {
    assertExactCallCount({
      source: "fn encrypt_core<R: SecureRandom + ?Sized>(rng: &mut R) {}",
      name: "encrypt_core",
      expected: 1,
      label: "primitive.rs",
      fail,
    });
  });
});

test("exact call policy rejects duplicate semantic delegation", () => {
  assert.throws(
    () => {
      assertExactCallCount({
        source: "fn adapter() { sign_jws(input); sign_jws(input); }",
        name: "sign_jws",
        expected: 1,
        label: "adapter.rs",
        fail,
      });
    },
    PolicyFailure,
  );
});

test("forbidden token policy rejects direct provider bypass", () => {
  assert.throws(
    () => {
      assertForbiddenTokens({
        source: "reallyme_crypto::dispatch::sign(algorithm, key, input)",
        tokens: ["reallyme_crypto::dispatch"],
        label: "adapter.rs",
        fail,
      });
    },
    PolicyFailure,
  );
});

test("exclusive core policy rejects a third call site", () => {
  const sources = new Map([
    ["primitive.rs", "fn execute_core() {}"],
    ["semantic.rs", "fn execute() { execute_core(); }"],
    ["adapter.rs", "fn bypass() { execute_core(); }"],
  ]);
  assert.throws(
    () => {
      assertExclusiveCallSites({
        sources,
        name: "execute_core",
        expectedByFile: new Map([
          ["primitive.rs", 1],
          ["semantic.rs", 1],
        ]),
        fail,
      });
    },
    PolicyFailure,
  );
});

test("repository architecture satisfies the complete policy", () => {
  assert.doesNotThrow(() => {
    assertOperationContractArchitecture({
      readText: readRepositoryText,
      listFiles: listRepositoryFiles,
      fail,
    });
  });
});

test("complete policy rejects a wire semantic bypass", () => {
  const readText = (path) => {
    const source = readRepositoryText(path);
    if (path === "crates/jose/src/wire.rs") {
      return `${source}\nfn bypass(input: Input) { sign_jws(input); }\n`;
    }
    return source;
  };
  assert.throws(
    () => {
      assertOperationContractArchitecture({
        readText,
        listFiles: listRepositoryFiles,
        fail,
      });
    },
    PolicyFailure,
  );
});

test("complete policy rejects a protobuf primitive bypass", () => {
  const readText = (path) => {
    const source = readRepositoryText(path);
    if (path === "crates/jose/src/operation_contract/protobuf/jwt.rs") {
      return `${source}\nfn bypass() { encode_signed_jwt_claims_json_core(); }\n`;
    }
    return source;
  };
  assert.throws(
    () => {
      assertOperationContractArchitecture({
        readText,
        listFiles: listRepositoryFiles,
        fail,
      });
    },
    PolicyFailure,
  );
});

test("complete policy rejects an unauthorized core call site", () => {
  const readText = (path) => {
    const source = readRepositoryText(path);
    if (path === "crates/jose/src/lib.rs") {
      return `${source}\nfn bypass() { decode_unsigned_jwt_claims_json_core(); }\n`;
    }
    return source;
  };
  assert.throws(
    () => {
      assertOperationContractArchitecture({
        readText,
        listFiles: listRepositoryFiles,
        fail,
      });
    },
    PolicyFailure,
  );
});

test("complete policy rejects a provider dependency in the canonical response path", () => {
  const readText = (path) => {
    const source = readRepositoryText(path);
    if (path === "crates/jose/src/wire/operation_response.rs") {
      return `${source}\nuse reallyme_crypto::dispatch;\n`;
    }
    return source;
  };
  assert.throws(
    () => {
      assertOperationContractArchitecture({
        readText,
        listFiles: listRepositoryFiles,
        fail,
      });
    },
    PolicyFailure,
  );
});
