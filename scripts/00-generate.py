import argparse
import base58
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import json

def parse_args(arg_list=None):
    parser = argparse.ArgumentParser(
        description='Generate private/public keys and DID document')
    parser.add_argument('-f', dest='output_keyfile', required=True,
                        help='Outputs to indicated keyfile')
    parser.add_argument('-d', dest='domain_name', required=True,
                        help='Used for ID of the DID document')
    return parser.parse_args(arg_list)

def generate_private_key():
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key

def get_bytes_from_private_key(private_key: ed25519.Ed25519PrivateKey):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw)
    return private_bytes, public_bytes

def generate_did_document(public_bytes: bytes, domain_name: str):
    did = f'did:web:{domain_name}'
    public_key_b58 = base58.b58encode(public_bytes).decode('ascii')
    return {
        '@Context': [
            'https://www.w3.org/ns/did/v1',
            'https://digitalbazaar.github.io/ed25519-signature-2018-context/contexts/ed25519-signature-2018-v1.jsonld'
        ],
        'id': did,
        'verificationMethod': [
            {
                'id': f'{did}#owner',
                'type': 'Ed25519VerificationKey2018',
                'controller': did,
                'publicKeyBase58': public_key_b58
            }
        ],
        'authentication': [
            f'{did}#owner'
        ]
    }

def write_bytes(bytes: bytes, path: str):
    with open(path, 'wb') as f:
        f.write(bytes)

def write_dict(obj: dict, path: str):
    with open(path, 'w') as f:
        json.dump(obj, f, indent=4)

def main(arg_list=None):
    print('Generate public/private Ed25519 key pair and DID document.')
    args = parse_args(arg_list)
    output_keyfile = (
        args.output_keyfile
        or input('Enter file in which to save the key and DID document: '))
    domain_name = (
        args.domain_name
        or input('Enter domain name used to generate the DID document: '))
    private_key = generate_private_key()
    private_bytes, public_bytes = get_bytes_from_private_key(private_key)
    write_bytes(private_bytes, output_keyfile)
    print(f'Your identification has been saved in {output_keyfile}')
    write_bytes(public_bytes, f'{output_keyfile}.pub')
    print(f'Your public key has been saved in {output_keyfile}.pub')
    did_document = generate_did_document(public_bytes, domain_name)
    write_dict(did_document, f'{output_keyfile}.did.json')
    print(f'Your DID document has been saved in {output_keyfile}.did.json')

if __name__ == '__main__':
    main()
