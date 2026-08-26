import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  base58btcDecode,
  base58btcEncode,
  createIdentity,
  createReceipt,
  createSignedMessage,
  didFingerprint,
  didFromPrivateKey,
  loadIdentity,
  normalizeMessage,
  publicKeyFromDid,
  saveSignedReceipt,
  verifyReceipt,
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
  assert.equal(publicKeyFromDid(createdDid).asymmetricKeyType, "ed25519");
  assert.equal(
    didFingerprint(createdDid),
    createHash("sha256").update(createdDid, "utf8").digest("hex").slice(0, 16),
  );
  await assert.rejects(
    loadIdentity(identityPath, "wrong-test-passphrase"),
    /incorrect passphrase/,
  );

  assert.equal(normalizeMessage("  hello\nworld\u200d  "), "hello world");

  const nonce = "1787609187558102000";
  const signed = createSignedMessage(
    privateKey,
    "lobby",
    "Hello Technocore",
    nonce,
  );
  assert.equal(signed.did, createdDid);
  assert.equal(signed.nonce, nonce);
  assert.equal(signed.text, "Hello Technocore");
  assert.throws(
    () => createSignedMessage(privateKey, "lobby", "Numeric nonce", 123),
    /nonce must contain/,
  );
  assert.throws(
    () =>
      createSignedMessage(
        privateKey,
        "lobby",
        "Inexact JSON nonce",
        "1234567890123456789",
      ),
    /round-trip exactly/,
  );

  const generatedNonceA = createSignedMessage(
    privateKey,
    "lobby",
    "Nonce round-trip A",
  ).nonce;
  const generatedNonceB = createSignedMessage(
    privateKey,
    "lobby",
    "Nonce round-trip B",
  ).nonce;
  assert.equal(
    String(JSON.parse(JSON.stringify(Number(generatedNonceA)))),
    generatedNonceA,
  );
  assert.equal(
    String(JSON.parse(JSON.stringify(Number(generatedNonceB)))),
    generatedNonceB,
  );
  assert.equal(generatedNonceA.length, 19);
  assert.equal(generatedNonceB.length, 19);
  assert.ok(BigInt(generatedNonceB) > BigInt(generatedNonceA));
  let previousGeneratedNonce = generatedNonceB;
  for (let index = 0; index < 128; index += 1) {
    const current = createSignedMessage(
      privateKey,
      "lobby",
      `Nonce stress ${index}`,
    ).nonce;
    assert.equal(
      String(JSON.parse(JSON.stringify(Number(current)))),
      current,
    );
    assert.ok(BigInt(current) > BigInt(previousGeneratedNonce));
    previousGeneratedNonce = current;
  }

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

  const multibasePayload = createdDid.slice("did:key:z".length);
  assert.equal(
    base58btcEncode(base58btcDecode(multibasePayload)),
    multibasePayload,
  );
  assert.throws(() => base58btcDecode("0OIl"), /invalid character/);
  assert.throws(
    () => publicKeyFromDid(`${createdDid}1`),
    /Ed25519 did:key/,
  );

  const posted = {
    seq: 42,
    ts: "2026-08-26T12:34:56.123456Z",
    from: signed.did,
    text: signed.text,
    nonce: Number(signed.nonce),
  };
  const receipt = createReceipt({
    room: "lobby",
    posted,
    proof: {
      ...signed,
      canonical: `lobby|${nonce}|Hello Technocore`,
    },
  });
  const verifiedReceipt = verifyReceipt(receipt);
  assert.equal(verifiedReceipt.signatureValid, true);
  assert.equal(verifiedReceipt.authenticated.did, createdDid);
  assert.equal(verifiedReceipt.authenticated.room, "lobby");
  assert.equal(verifiedReceipt.unverifiedServerObservation.seq, 42);

  const serializedReceipt = JSON.stringify(receipt);
  assert.ok(!serializedReceipt.includes(passphrase));
  assert.ok(!serializedReceipt.includes("PRIVATE KEY"));
  assert.ok(!serializedReceipt.includes(pem));

  const mutate = (callback) => {
    const copy = JSON.parse(serializedReceipt);
    callback(copy);
    return copy;
  };
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.proof.text = "Changed";
        }),
      ),
    /canonical payload/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.proof.canonical += "!";
        }),
      ),
    /canonical payload/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.proof.sig = `${copy.proof.sig.slice(0, -1)}${
            copy.proof.sig.endsWith("A") ? "B" : "A"
          }`;
        }),
      ),
    /signature verification failed/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.proof.did = `${copy.proof.did.slice(0, -1)}${
            copy.proof.did.endsWith("1") ? "2" : "1"
          }`;
        }),
      ),
    /(signature verification failed|invalid Ed25519 multicodec payload)/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.posted.text = "Changed";
        }),
      ),
    /posted metadata/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.posted.nonce = copy.proof.nonce;
        }),
      ),
    /posted metadata/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.posted.seq = 0;
        }),
      ),
    /posted metadata/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.posted.ts = "yesterday";
        }),
      ),
    /posted metadata/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.service = "https://example.com";
        }),
      ),
    /receipt service/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.verified = true;
        }),
      ),
    /unsupported fields/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.proof.github_account = "someone-else";
        }),
      ),
    /unsupported fields/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.posted.reward_eligible = true;
        }),
      ),
    /unsupported fields/,
  );
  assert.throws(
    () =>
      verifyReceipt(
        mutate((copy) => {
          copy.room = 123;
          copy.proof.canonical = `123|${nonce}|Hello Technocore`;
        }),
      ),
    /room must match/,
  );

  const reservedReceiptPath = join(testRoot, "already-exists.json");
  await writeFile(reservedReceiptPath, "do not replace", "utf8");
  await assert.rejects(
    saveSignedReceipt(
      privateKey,
      "lobby",
      "This must fail before any network write",
      reservedReceiptPath,
    ),
    /refusing to overwrite existing receipt/,
  );
  assert.equal(await readFile(reservedReceiptPath, "utf8"), "do not replace");

  await assert.rejects(
    createIdentity(identityPath, passphrase),
    /refusing to overwrite existing identity/,
  );

  console.log("All Technocore Node Helper tests passed");
} finally {
  await rm(testRoot, { recursive: true, force: true });
}
