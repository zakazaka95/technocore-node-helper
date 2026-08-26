#!/usr/bin/env node

/**
 * Minimal Technocore DID helper for Windows, macOS, and Linux.
 *
 * Uses only Node.js built-ins. The encrypted Ed25519 private key stays in
 * identity.pem. Network writes contain only the public DID, signature, nonce,
 * and public message text.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { chmod, open, readFile, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const VERSION = "1.2.0";
const DEFAULT_BASE_URL = "https://technocore.chat";
const DEFAULT_KEY_PATH = resolve(process.cwd(), "identity.pem");
const RECEIPT_TYPE = "technocore-signed-message-receipt";
const RECEIPT_VERSION = 1;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ROOM_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const INVISIBLE_PATTERN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;

function fail(message) {
  throw new Error(message);
}

export function base58btcEncode(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    fail("base58 input must be a non-empty Buffer");
  }

  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes += 1;
  }

  let number = BigInt(`0x${bytes.toString("hex")}`);
  let encoded = "";
  while (number > 0n) {
    const remainder = Number(number % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    number /= 58n;
  }

  return "1".repeat(leadingZeroes) + encoded;
}

export function base58btcDecode(text) {
  if (typeof text !== "string" || text.length === 0) {
    fail("base58 input must be a non-empty string");
  }

  let number = 0n;
  for (const character of text) {
    const value = BASE58_ALPHABET.indexOf(character);
    if (value < 0) fail("base58 input contains an invalid character");
    number = number * 58n + BigInt(value);
  }

  let decoded = Buffer.alloc(0);
  if (number > 0n) {
    let hex = number.toString(16);
    if (hex.length % 2 !== 0) hex = `0${hex}`;
    decoded = Buffer.from(hex, "hex");
  }

  let leadingZeroes = 0;
  while (leadingZeroes < text.length && text[leadingZeroes] === "1") {
    leadingZeroes += 1;
  }
  const result = Buffer.concat([Buffer.alloc(leadingZeroes), decoded]);
  if (base58btcEncode(result) !== text) {
    fail("base58 input is not canonical");
  }
  return result;
}

function rawPublicKey(key) {
  const publicKey = createPublicKey(key);
  if (publicKey.asymmetricKeyType !== "ed25519") {
    fail("identity must contain an Ed25519 private key");
  }

  const der = publicKey.export({ type: "spki", format: "der" });
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    fail("identity has an unexpected Ed25519 public-key encoding");
  }
  return der.subarray(ED25519_SPKI_PREFIX.length);
}

export function didFromPrivateKey(privateKey) {
  const multibase =
    "z" +
    base58btcEncode(Buffer.concat([ED25519_MULTICODEC, rawPublicKey(privateKey)]));
  if (multibase.length !== 48 || !multibase.startsWith("z6Mk")) {
    fail("generated an invalid Ed25519 did:key");
  }
  return `did:key:${multibase}`;
}

export function publicKeyFromDid(did) {
  if (
    typeof did !== "string" ||
    !/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(did)
  ) {
    fail("receipt DID must be an Ed25519 did:key");
  }
  const multibase = did.slice("did:key:".length);
  const decoded = base58btcDecode(multibase.slice(1));
  if (
    decoded.length !== ED25519_MULTICODEC.length + 32 ||
    !decoded.subarray(0, ED25519_MULTICODEC.length).equals(ED25519_MULTICODEC)
  ) {
    fail("receipt DID has an invalid Ed25519 multicodec payload");
  }
  return createPublicKey({
    key: Buffer.concat([
      ED25519_SPKI_PREFIX,
      decoded.subarray(ED25519_MULTICODEC.length),
    ]),
    type: "spki",
    format: "der",
  });
}

export function didFingerprint(did) {
  publicKeyFromDid(did);
  return createHash("sha256").update(did, "utf8").digest("hex").slice(0, 16);
}

export function normalizeMessage(text) {
  if (typeof text !== "string") {
    fail("message text must be a string");
  }
  const normalized = text.replace(INVISIBLE_PATTERN, " ").trim();
  if (!normalized) {
    fail("message has no visible text after normalization");
  }
  if ([...normalized].length > 4096) {
    fail("message must be no longer than 4096 characters");
  }
  return normalized;
}

function validateRoom(room) {
  if (typeof room !== "string" || !ROOM_PATTERN.test(room)) {
    fail("room must match ^[a-z0-9][a-z0-9_-]{0,47}$");
  }
  return room;
}

function requireExactKeys(value, expectedKeys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} contains missing or unsupported fields`);
  }
}

async function promptHidden(label) {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    fail("a real terminal is required for the hidden passphrase prompt");
  }

  process.stderr.write(label);
  process.stdin.setEncoding("utf8");
  process.stdin.setRawMode(true);
  process.stdin.resume();

  return new Promise((resolvePrompt, rejectPrompt) => {
    let value = "";

    const restore = () => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
    };

    const onData = (chunk) => {
      for (const character of chunk) {
        if (character === "\u0003") {
          restore();
          process.stderr.write("\n");
          rejectPrompt(new Error("cancelled"));
          return;
        }
        if (character === "\r" || character === "\n") {
          restore();
          process.stderr.write("\n");
          resolvePrompt(value);
          return;
        }
        if (character === "\b" || character === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        value += character;
      }
    };

    process.stdin.on("data", onData);
  });
}

export async function createIdentity(path, passphrase) {
  if (typeof passphrase !== "string" || [...passphrase].length < 12) {
    fail("identity passphrase must contain at least 12 characters");
  }

  const { privateKey } = generateKeyPairSync("ed25519");
  const encryptedPem = privateKey.export({
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase,
  });

  let handle;
  let created = false;
  try {
    handle = await open(path, "wx", 0o600);
    created = true;
    await handle.writeFile(encryptedPem, { encoding: "utf8" });
    await handle.sync();
  } catch (error) {
    if (error?.code === "EEXIST") {
      fail(`refusing to overwrite existing identity: ${path}`);
    }
    if (created) {
      await unlink(path).catch(() => {});
    }
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
  await chmod(path, 0o600).catch(() => {});
  return didFromPrivateKey(privateKey);
}

export async function loadIdentity(path, passphrase) {
  let pem;
  try {
    pem = await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      fail(`identity not found: ${path}`);
    }
    throw error;
  }

  let privateKey;
  try {
    privateKey = createPrivateKey({
      key: pem,
      format: "pem",
      passphrase,
    });
  } catch {
    fail("incorrect passphrase or invalid encrypted identity");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    fail("identity must contain an Ed25519 private key");
  }
  return privateKey;
}

let lastNonce = 0n;

function jsonCanonicalInteger(value) {
  const text = String(Number(value));
  if (!/^[0-9]{1,19}$/.test(text)) {
    fail("cannot generate a canonical 1-19 digit JSON nonce");
  }
  return BigInt(text);
}

function nextNonce() {
  // Preserve the helper's original microsecond-scale clock so an updated
  // client still counts above its recent room messages. Technocore returns
  // nonce as a JSON number, so use the decimal spelling JavaScript will emit
  // again after parsing that response.
  const raw =
    BigInt(Date.now()) * 1_000_000n +
    (process.hrtime.bigint() % 1_000_000n);
  let nonce = jsonCanonicalInteger(raw);
  let attempts = 0;
  while (nonce <= lastNonce && attempts < 8) {
    const bitLength = (lastNonce + 1n).toString(2).length;
    const quantum = 1n << BigInt(Math.max(0, bitLength - 53));
    nonce = jsonCanonicalInteger(lastNonce + quantum * BigInt(attempts + 1));
    attempts += 1;
  }
  if (nonce <= lastNonce || String(Number(nonce)) !== nonce.toString()) {
    fail("cannot generate a monotonic JSON nonce on this system clock");
  }
  lastNonce = nonce;
  return nonce.toString();
}

export function createSignedMessage(privateKey, room, text, nonce = nextNonce()) {
  const validRoom = validateRoom(room);
  const normalized = normalizeMessage(text);
  if (typeof nonce !== "string" || !/^[0-9]{1,19}$/.test(nonce)) {
    fail("nonce must contain 1-19 ASCII digits");
  }
  if (!Number.isInteger(Number(nonce)) || String(Number(nonce)) !== nonce) {
    fail("nonce must round-trip exactly through a Technocore JSON response");
  }

  const did = didFromPrivateKey(privateKey);
  const payload = Buffer.from(`${validRoom}|${nonce}|${normalized}`, "utf8");
  const signature = sign(null, payload, privateKey).toString("base64url");
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) {
    fail("generated an invalid Ed25519 signature");
  }
  return { did, sig: signature, nonce, text: normalized };
}

export async function postSignedMessage(privateKey, room, text) {
  const validRoom = validateRoom(room);
  const body = createSignedMessage(privateKey, validRoom, text);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20_000);

  let response;
  try {
    response = await fetch(
      `${DEFAULT_BASE_URL}/r/${encodeURIComponent(validRoom)}?format=json`,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": `technocore-node-helper/${VERSION}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      },
    );
  } finally {
    clearTimeout(timeout);
  }

  const responseText = await response.text();
  if (!response.ok) {
    fail(`Technocore returned HTTP ${response.status}: ${responseText.slice(0, 500)}`);
  }

  let result;
  try {
    result = JSON.parse(responseText);
  } catch {
    fail("Technocore returned a non-JSON response");
  }

  const posted = result?.posted;
  if (
    result?.room !== validRoom ||
    posted?.from !== body.did ||
    String(posted?.nonce) !== body.nonce ||
    posted?.text !== body.text ||
    !Number.isSafeInteger(posted?.seq) ||
    posted.seq < 1
  ) {
    fail("Technocore returned a posted record that does not match this identity");
  }
  return {
    ...result,
    proof: {
      ...body,
      canonical: `${validRoom}|${body.nonce}|${body.text}`,
    },
  };
}

export function createReceipt(result) {
  return {
    type: RECEIPT_TYPE,
    version: RECEIPT_VERSION,
    service: DEFAULT_BASE_URL,
    room: result.room,
    posted: {
      seq: result.posted.seq,
      ts: result.posted.ts,
      from: result.posted.from,
      text: result.posted.text,
      nonce: result.posted.nonce,
    },
    proof: {
      did: result.proof.did,
      sig: result.proof.sig,
      nonce: result.proof.nonce,
      text: result.proof.text,
      canonical: result.proof.canonical,
    },
  };
}

function receiptNonceMatches(postedNonce, proofNonce) {
  return (
    typeof postedNonce === "number" &&
    Number.isInteger(postedNonce) &&
    postedNonce >= 0 &&
    String(postedNonce) === proofNonce
  );
}

export function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    fail("receipt must be a JSON object");
  }
  requireExactKeys(
    receipt,
    ["type", "version", "service", "room", "posted", "proof"],
    "receipt",
  );
  if (receipt.type !== RECEIPT_TYPE || receipt.version !== RECEIPT_VERSION) {
    fail("unsupported Technocore receipt type or version");
  }
  if (receipt.service !== DEFAULT_BASE_URL) {
    fail(`receipt service must be ${DEFAULT_BASE_URL}`);
  }

  const room = validateRoom(receipt.room);
  const proof = receipt.proof;
  const posted = receipt.posted;
  if (
    !proof ||
    typeof proof !== "object" ||
    Array.isArray(proof) ||
    !posted ||
    typeof posted !== "object" ||
    Array.isArray(posted)
  ) {
    fail("receipt must contain posted and proof objects");
  }
  requireExactKeys(proof, ["did", "sig", "nonce", "text", "canonical"], "proof");
  requireExactKeys(posted, ["seq", "ts", "from", "text", "nonce"], "posted");

  if (typeof proof.nonce !== "string" || !/^[0-9]{1,19}$/.test(proof.nonce)) {
    fail("receipt nonce must contain 1-19 ASCII digits");
  }
  if (typeof proof.text !== "string") fail("receipt text must be a string");
  if (normalizeMessage(proof.text) !== proof.text) {
    fail("receipt text is not in canonical normalized form");
  }
  const canonical = `${room}|${proof.nonce}|${proof.text}`;
  if (proof.canonical !== canonical) {
    fail("receipt canonical payload does not match its fields");
  }
  if (
    typeof proof.sig !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(proof.sig)
  ) {
    fail("receipt signature must be canonical unpadded base64url");
  }

  const publicKey = publicKeyFromDid(proof.did);
  const signature = Buffer.from(proof.sig, "base64url");
  if (
    signature.length !== 64 ||
    signature.toString("base64url") !== proof.sig ||
    !verify(null, Buffer.from(canonical, "utf8"), publicKey, signature)
  ) {
    fail("receipt signature verification failed");
  }

  if (
    posted.from !== proof.did ||
    posted.text !== proof.text ||
    !receiptNonceMatches(posted.nonce, proof.nonce) ||
    !Number.isSafeInteger(posted.seq) ||
    posted.seq < 1 ||
    typeof posted.ts !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(
      posted.ts,
    ) ||
    !Number.isFinite(Date.parse(posted.ts))
  ) {
    fail("posted metadata is inconsistent with the signed proof");
  }

  return {
    signatureValid: true,
    authenticated: {
      did: proof.did,
      fingerprint: didFingerprint(proof.did),
      room,
      nonce: proof.nonce,
      text: proof.text,
      canonical,
    },
    unverifiedServerObservation: {
      service: receipt.service,
      seq: posted.seq,
      ts: posted.ts,
      internallyConsistent: true,
    },
  };
}

export async function saveSignedReceipt(privateKey, room, text, path) {
  let handle;
  let complete = false;
  try {
    handle = await open(path, "wx", 0o644);
  } catch (error) {
    if (error?.code === "EEXIST") {
      fail(`refusing to overwrite existing receipt: ${path}`);
    }
    throw error;
  }

  try {
    const result = await postSignedMessage(privateKey, room, text);
    const receipt = createReceipt(result);
    verifyReceipt(receipt);
    await handle.writeFile(`${JSON.stringify(receipt, null, 2)}\n`, "utf8");
    await handle.sync();
    complete = true;
    return receipt;
  } finally {
    await handle?.close().catch(() => {});
    if (!complete) await unlink(path).catch(() => {});
    else await chmod(path, 0o644).catch(() => {});
  }
}

function usage() {
  return `Technocore DID helper ${VERSION}

Run in the folder where identity.pem should be stored:
  node technocore-did-helper.mjs init
  node technocore-did-helper.mjs did
  node technocore-did-helper.mjs say <room> "<public message>"
  node technocore-did-helper.mjs receipt <room> <output.json> "<public message>"
  node technocore-did-helper.mjs verify-receipt <receipt.json>

Keep identity.pem and its passphrase private. Publish only the did:key value.`;
}

async function main(args) {
  const [command, ...rest] = args;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.log(usage());
    return;
  }
  if (command === "--version" || command === "-v") {
    console.log(VERSION);
    return;
  }

  if (command === "init") {
    if (rest.length !== 0) fail("init does not accept additional arguments");
    const first = await promptHidden("Create a passphrase (12+ characters): ");
    const second = await promptHidden("Repeat the passphrase: ");
    if (first !== second) fail("passphrases do not match");
    const did = await createIdentity(DEFAULT_KEY_PATH, first);
    console.log(did);
    console.error(`Encrypted identity created: ${DEFAULT_KEY_PATH}`);
    return;
  }

  if (command === "did") {
    if (rest.length !== 0) fail("did does not accept additional arguments");
    const passphrase = await promptHidden("Identity passphrase: ");
    const privateKey = await loadIdentity(DEFAULT_KEY_PATH, passphrase);
    console.log(didFromPrivateKey(privateKey));
    return;
  }

  if (command === "say") {
    if (rest.length < 2) fail('usage: say <room> "<public message>"');
    const room = rest[0];
    const text = rest.slice(1).join(" ");
    const passphrase = await promptHidden("Identity passphrase: ");
    const privateKey = await loadIdentity(DEFAULT_KEY_PATH, passphrase);
    const result = await postSignedMessage(privateKey, room, text);
    console.log(
      JSON.stringify(
        { room: result.room, posted: result.posted, proof: result.proof },
        null,
        2,
      ),
    );
    return;
  }

  if (command === "receipt") {
    if (rest.length < 3) {
      fail('usage: receipt <room> <output.json> "<public message>"');
    }
    const room = rest[0];
    const outputPath = resolve(process.cwd(), rest[1]);
    const text = rest.slice(2).join(" ");
    const passphrase = await promptHidden("Identity passphrase: ");
    const privateKey = await loadIdentity(DEFAULT_KEY_PATH, passphrase);
    const receipt = await saveSignedReceipt(
      privateKey,
      room,
      text,
      outputPath,
    );
    console.log(
      JSON.stringify(
        {
          receipt: outputPath,
          did: receipt.proof.did,
          room: receipt.room,
          seq: receipt.posted.seq,
        },
        null,
        2,
      ),
    );
    return;
  }

  if (command === "verify-receipt") {
    if (rest.length !== 1) fail("usage: verify-receipt <receipt.json>");
    const receiptPath = resolve(process.cwd(), rest[0]);
    let receipt;
    try {
      receipt = JSON.parse(await readFile(receiptPath, "utf8"));
    } catch (error) {
      if (error?.code === "ENOENT") fail(`receipt not found: ${receiptPath}`);
      fail(`invalid receipt JSON: ${error.message}`);
    }
    const verified = verifyReceipt(receipt);
    console.log(`valid Ed25519 signature for ${verified.authenticated.did}`);
    console.log(`authenticated payload: ${verified.authenticated.canonical}`);
    console.log(
      `unverified server observation: ${verified.unverifiedServerObservation.service} seq ${verified.unverifiedServerObservation.seq}, ts ${verified.unverifiedServerObservation.ts}`,
    );
    console.log(
      "The signature does not prove server acceptance, time, linked claims, or reward eligibility.",
    );
    return;
  }

  fail(`unknown command: ${command}\n\n${usage()}`);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  });
}
