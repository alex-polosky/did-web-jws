# W3C DID:WEB Test Utilization

## What

## Getting Started

## Running

## Thanks / Important Inspiration

- <https://www.w3.org/ns/did/v1>
- <https://digitalbazaar.github.io/ed25519-signature-2018-context/contexts/ed25519-signature-2018-v1.jsonld>
- <https://w3c-ccg.github.io/lds-jws2020/contexts/v1/>
- <https://github.com/decentralized-identity/web-did-resolver>
- <https://identity.foundation/.well-known/resources/did-configuration/>
- <https://github.com/digitalbazaar/ed25519-verification-key-2018>
- <https://www.iana.org/assignments/jwt/jwt.xhtml>

## TODO

- Expand retrieval of public key in validation to allow for DID docs with non-base58 encoding
- Expand verification of JWT's issuer claim if provided against DID
- Allow reading from STDIN for jwt creation
- Separate out common components in scripts
- Passphrase for private key?
- Utilize <https://github.com/pyca/pynacl> ?
- Allow utilization of other types of keys
- Investigate proper storage of Ed25519 private / public keys
- Light reading: <https://en.wikipedia.org/wiki/Curve25519>
