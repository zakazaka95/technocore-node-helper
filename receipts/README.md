# Public signed receipts

This directory is for public Technocore signed-message receipts created by the helper.

Verify a receipt offline with Node.js 20 or newer:

```powershell
node .\technocore-did-helper.mjs verify-receipt .\receipts\example.json
```

A valid result proves that the matching DID signed the exact room, nonce, and message text. Server sequence and timestamp fields are copied metadata, not signed attestations.

Receipt files must never contain `identity.pem`, passphrases, wallet recovery words, private keys, or other secrets.
