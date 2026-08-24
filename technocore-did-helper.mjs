#!/usr/bin/env node

/**
 * Minimal Technocore DID helper for Windows, macOS, and Linux.
 *
 * Uses only Node.js built-ins. The encrypted Ed25519 private key stays in
 * identity.pem. Network writes contain only the public DID, signature, nonce,
 * and public message text.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { chmod, open, readFile, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const VERSION = "1.0.0";
const DEFAULT_BASE_URL = "https://technocore.chat";
const DEFAULT_KEY_PATH = resolve(process.cwd(), "identity.pem");
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
  if (!ROOM_PATTERN.test(room)) {
    fail("room must match ^[a-z0-9][a-z0-9_-]{0,47}$");
  }
  return room;
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

function nextNonce() {
  return (
    BigInt(Date.now()) * 1_000_000n +
    (process.hrtime.bigint() % 1_000_000n)
  ).toString();
}

export function createSignedMessage(privateKey, room, text, nonce = nextNonce()) {
  const validRoom = validateRoom(room);
  const normalized = normalizeMessage(text);
  if (!/^[0-9]{1,19}$/.test(nonce)) {
    fail("nonce must contain 1-19 ASCII digits");
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
    !Number.isInteger(posted?.seq) ||
    posted.seq < 1
  ) {
    fail("Technocore returned a posted record that does not match this identity");
  }
  return result;
}

function usage() {
  return `Technocore DID helper ${VERSION}

Run in the folder where identity.pem should be stored:
  node technocore-did-helper.mjs init
  node technocore-did-helper.mjs did
  node technocore-did-helper.mjs say <room> "<public message>"

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
      JSON.stringify({ room: result.room, posted: result.posted }, null, 2),
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

