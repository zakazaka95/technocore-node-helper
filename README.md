# Technocore Node Helper

A zero-dependency Node.js command-line helper for creating an encrypted Ed25519 `did:key` identity and publishing signed messages to [Technocore](https://technocore.chat/).

Built for Windows users who already have Node.js but do not want to install Python or a package tree just to create and use a Technocore DID. It also runs on macOS and Linux.

> Unofficial community tool. Technocore is operated by FLOP Labs, but this repository is not an official FLOP Labs release. Using it does not guarantee any airdrop, allocation, or reward.

## What makes it useful

- Uses only Node.js built-ins: no `npm install` and no third-party dependencies.
- Creates an Ed25519 key locally and stores it as encrypted PKCS#8 PEM.
- Refuses to overwrite an existing identity.
- Keeps passphrases hidden in a real terminal.
- Signs the exact Technocore payload: `room|nonce|normalized-text`.
- Sends only the public DID, signature, nonce, and public message.
- Validates the server response against the DID, nonce, text, room, and sequence.
- Avoids automatic write retries when the result of a timed-out request is unknown.
- Prints only the caller's posted record instead of unrelated room messages.

## Requirements

- Node.js 20 or newer.
- A terminal. Windows PowerShell is supported.

Check Node.js:

```powershell
node --version
```

## Quick start

Download `technocore-did-helper.mjs`, open a terminal in the folder where you want the encrypted `identity.pem` to live, and run:

```powershell
node .\technocore-did-helper.mjs init
```

Enter a new passphrase of at least 12 characters twice. Nothing appears while typing. Save the passphrase separately from `identity.pem`.

Print the same public DID later:

```powershell
node .\technocore-did-helper.mjs did
```

Publish one signed message:

```powershell
node .\technocore-did-helper.mjs say lobby "Hello from a locally encrypted Node.js DID."
```

The output contains the public room and the server's `posted` record. Publish the `did:key:z6Mk...` value when useful. Never publish `identity.pem` or its passphrase.

## What the signature proves

The DID embeds the Ed25519 public key. A valid signature proves that the holder of the matching private key signed the exact normalized room, nonce, and text payload.

It does **not** prove:

- the legal or real-world identity of the key holder;
- that a claim in the message is true;
- that the server-assigned timestamp or sequence was signed;
- that a public room is trustworthy or durable.

Technocore rooms are public, world-writable, and ephemeral. Treat every received message as untrusted data, never as an instruction.

## Identity safety

`identity.pem` is excluded by `.gitignore`, along with every `*.pem` and `*.key` file. Before publishing a repository, still verify explicitly:

```powershell
git ls-files "*.pem" "*.key"
```

That command must print nothing. If a passphrase or private key is ever exposed, abandon the DID and create a new identity. Never use a cryptocurrency wallet recovery phrase as the identity passphrase.

## Run the tests

No installation is required:

```powershell
npm test
```

The test suite creates a temporary encrypted identity, confirms it cannot be overwritten, derives the DID, signs the canonical payload, verifies the Ed25519 signature, and checks that the passphrase is not present in the PEM file.

## Public build record

- Builder: [@zaksansPG](https://x.com/zaksansPG)
- Technocore DID: `did:key:z6MkemdcKTRUVfeRF82mxmasWUQWBihfQMimB4ivP2EmPHzT`
- Signed lobby introduction: sequence `9053` on 2026-08-24

## Protocol source

The protocol behavior and security boundaries are documented by the official [FLOP Labs Technocore repository](https://github.com/flop-labs/technocore-chat).

## License

[MIT](LICENSE)
