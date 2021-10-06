# W3C DID:WEB Test Utilization

## What

An exercise in creating DID documents and interacting with them through JWT tokens. Can be extrapolated to create decentralized servers and trust platforms utilizing the generated keys.

## Getting Started

- Clone this repository via `git clone git@github.com:alex-polosky/did-web-jws.git`
- Run `cd webapp` to ensure commands take place in the correct directory
- Copy `./.env.template` to `./.env`
- Generate `SECRET_KEY` for the `.env` file (recommend `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"` via [this SO post](https://stackoverflow.com/questions/54498123/django-secret-key-generation))
- Run the following commands to setup the Django server
  - `./manage.py migrate` to setup the database
  - `./manage.py createsuperuser` to create the superuser for Django
  - `./manage.py runserver` to start the Django server

## Running

- Run 00, placing DID DOC in webapp
  - `python scripts/00-generate.py -f [output_file] -d [localhost:8000]`
  - Copy `[output_file].did.json` into `webapp/did.json`
- Run 01
  - Create a sample payload; one is provided at ./data/payload.json
  - `python scripts/01-create-jwt.py -i [output_file] -o [payload.jwt] data/payload.json`
- Run 02
  - `python scripts/02-validate.py -f [payload.jwt] did:web:localhost:8000`
  - If everything was succesful, the command line should show: `Token validated successfully`

Please note that everything _can_ be ran through vscode, even debugged. Arguments may be passed to each script's `main` function as if they were arguments on the command line to facilitate debugging `Python: Current File`. This is helpful to view how all of the pieces fit together.

---

### Notice

The keys provided as samples in this project (`data/*`) _should never_ be used in a production setting

---

## Thanks / Important Inspiration

- <https://www.w3.org/ns/did/v1>
- <https://digitalbazaar.github.io/ed25519-signature-2018-context/contexts/ed25519-signature-2018-v1.jsonld>
- <https://w3c-ccg.github.io/lds-jws2020/contexts/v1/>
- <https://github.com/decentralized-identity/web-did-resolver>
- <https://identity.foundation/.well-known/resources/did-configuration/>
- <https://w3c-ccg.github.io/security-vocab/#Ed25519Signature2018>
- <https://github.com/digitalbazaar/ed25519-verification-key-2018>
- <https://www.iana.org/assignments/jwt/jwt.xhtml>

## TODO

- Tests, especially for 02-validate.py:DEV_MODE
- Expand retrieval of public key in validation to allow for DID docs with non-base58 encoding
- Expand verification of JWT's issuer claim if provided against DID
- Allow reading from STDIN for jwt creation
- Separate out common components in scripts
- Passphrase for private key?
- Utilize <https://github.com/pyca/pynacl> ?
- Allow utilization of other types of keys
- Investigate proper storage of Ed25519 private / public keys
- Light reading: <https://en.wikipedia.org/wiki/Curve25519>
- Follow up on the RFC proposal for DID / DID:WEB and adjust accordingly
