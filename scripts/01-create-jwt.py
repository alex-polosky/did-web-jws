import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
import json
import jwt
import sys

JWT_ALGORITHM = 'EdDSA'

def parse_args(arg_list=None):
    parser = argparse.ArgumentParser(
        description='Generate signed JWT token from payload')
    parser.add_argument('-i', dest='identity_file', required=True,
                        help='Location of the private key file')
    parser.add_argument('-o', dest='output_file', required=False,
                        help='Output file for the JWT token')
    parser.add_argument('filename',
                        help='Location of payload as a file')

    return parser.parse_args(arg_list)

def main():
    args = parse_args()
    identity_file = args.identity_file
    output_file = args.output_file
    with open(args.filename) as f:
        payload = json.load(f)

    with open(identity_file, 'rb') as f:
        private_bytes = f.read()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)

    jwt_text = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(jwt_text)
    sys.stdout.write(jwt_text)  # Don't output newline

if __name__ == '__main__':
    main()
