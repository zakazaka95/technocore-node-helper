import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createIdentity,
  createSignedMessage,
  didFromPrivateKey,
  loadIdentity,
  normalizeMessage,
} from "./technocore-did-helper.mjs";

const testRoot = await mkdtemp(join(tmpdir(), "technocore-node-helper-"));
const identityPath = join(testRoot, "identity.pem");
const passphrase = "test-only-passphrase-123";

try {
  const createdDid = await createIdentity(identityPath, passphrase);
  assert.match(createdDid, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);

  const pem = await readFile(identityPath, "utf8");
  assert.match(pem, /^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
  assert.ok(!pem.includes(passphrase));

  const privateKey = await loadIdentity(identityPath, passphrase);
  assert.equal(didFromPrivateKey(privateKey), createdDid);
  await assert.rejects(
    loadIdentity(identityPath, "wrong-test-passphrase"),
    /incorrect passphrase/,
  );

  assert.equal(normalizeMessage("  hello\nworld\u200d  "), "hello world");

  const nonce = "1234567890123456789";
  const signed = createSignedMessage(
    privateKey,
    "lobby",
    "Hello Technocore",
    nonce,
  );
  assert.equal(signed.did, createdDid);
  assert.equal(signed.nonce, nonce);
  assert.equal(signed.text, "Hello Technocore");

  const payload = Buffer.from(`lobby|${nonce}|Hello Technocore`, "utf8");
  assert.equal(
    verify(
      null,
      payload,
      createPublicKey(privateKey),
      Buffer.from(signed.sig, "base64url"),
    ),
    true,
  );

  await assert.rejects(
    createIdentity(identityPath, passphrase),
    /refusing to overwrite existing identity/,
  );

  console.log("All Technocore Node Helper tests passed");
} finally {
  await rm(testRoot, { recursive: true, force: true });
}
