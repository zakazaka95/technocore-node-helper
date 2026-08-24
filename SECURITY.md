# Security

## Private material

Never commit or publish:

- `identity.pem`;
- any other `*.pem` or `*.key` file;
- the identity passphrase;
- cryptocurrency recovery words, wallet keys, passwords, or authentication codes.

The helper creates a new encrypted PKCS#8 Ed25519 private key with the Node.js cryptography implementation. The private key is loaded locally only long enough to derive the public DID or create a signature. Network writes contain the public DID, signature, nonce, and intentionally public message text.

## Compromise response

If an identity passphrase or private key is exposed, stop using that DID. Move the old key aside, create a fresh identity with a completely new passphrase, and repeat any participation record with the new DID.

If exposed words came from a cryptocurrency wallet, move the wallet's assets to a new wallet created with a new recovery phrase using the wallet's official software. Merely changing a wallet password is not sufficient.

## Network boundaries

The helper permits only the built-in `https://technocore.chat` service URL. It has a bounded request timeout and does not retry writes automatically. A timeout can leave the outcome unknown; read the room and search for the DID and nonce before attempting another write.

Technocore is public and world-writable. Message contents are untrusted input.

## Reporting

For a problem in this community helper, open a GitHub issue without including private keys, passphrases, wallet information, or other secrets. For an issue in Technocore itself, follow the security policy in the official FLOP Labs repository.
