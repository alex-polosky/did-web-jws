import argparse
import base58
from cryptography.hazmat.primitives.asymmetric import ed25519
import jwt

JWT_ALGORITHM = 'EdDSA'

def parse_args(arg_list=None):
    parser = argparse.ArgumentParser(
        description='Verify signed JWT token from payload via DID:WEB')
    parser.add_argument('-f', dest='jwt_file', required=True,
                        help='Location of the file containing the jwt')
    parser.add_argument('host',
                        help='Host of the DID:WEB document')

    return parser.parse_args(arg_list)

def get_public_key(host):
    import json
    with open(host) as f:
        data = json.load(f)
    # Assume Base 58 encoding due to DID:WEB specs
    public_key_58 = data['verificationMethod'][0]['publicKeyBase58']
    public_bytes = base58.b58decode(public_key_58)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    return public_key

def main(arg_list=None):
    args = parse_args(arg_list)
    with open(args.jwt_file) as f:
        jwt_text = f.read()

    public_key = get_public_key(args.host)
    decoded_text = jwt.decode(jwt_text, public_key, JWT_ALGORITHM)
    print(decoded_text)

if __name__ == '__main__':
    main(['-f', 'data/payload.jwt', 'data/sample.did.json'])
