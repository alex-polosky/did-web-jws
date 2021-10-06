import argparse
import base58
from cryptography.hazmat.primitives.asymmetric import ed25519
import jwt
from jwt.exceptions import DecodeError, InvalidSignatureError, InvalidTokenError
import re
from urllib.parse import urlparse

# Note: DEV_MODE forces non-https, and allows utilization of ports other than
# 443 which breaks DID:WEB spec, but is useful for testing
DEV_MODE = True
JWT_ALGORITHM = 'EdDSA'

class DIDError(BaseException):
    def __init__(self, message):
        super().__init__(message)

class DIDSchemeError(DIDError):
    def __init__(self, message=None):
        super().__init__(message or 'URI must start with `did`')

class DIDWebURIError(DIDSchemeError):
    def __init__(self):
        super().__init__('DID URI must start with `did:web`')

def parse_args(arg_list=None):
    parser = argparse.ArgumentParser(
        description='Verify signed JWT token from payload via DID:WEB')
    parser.add_argument('-f', dest='jwt_file', required=True,
                        help='Location of the file containing the jwt')
    parser.add_argument('host',
                        help='Host of the DID:WEB document')

    return parser.parse_args(arg_list)

def get_public_key(host: str):
    def _via_file():
        import json
        with open(host) as f:
            data = json.load(f)
        return data
    def _via_http():
        import requests

        uri = urlparse(host)
        if uri.scheme != 'did':
            raise DIDSchemeError()
        if not uri.path.startswith('web:'):
            raise DIDWebURIError()
        
        # Technically speaking, allowing DID:WEB to exist on a port other than
        # 443 is out of spec, but for dev purposes it's a lot easier to test
        # and not have to deploy to a full fledged server
        # Note, this would never and should never be production code
        path = uri.path[4:]
        if DEV_MODE:
            detail_path = re.findall('[a-z0-9]*:(([0-9]{1,5})(:.*)?)|(:.*)', 
                                     path)
            if detail_path:
                path = path.split(':')[0]
                detail_path = detail_path[0]
                if detail_path[0]:
                    path = f'{path}:{detail_path[1]}{detail_path[2].replace(":", "/")}'
                else:
                    path = f'{path}{detail_path[3].replace(":", "/")}'
        else:
            path = path.replace(':', '/')

        if path.count('/') == 0:
            path += '/.well-known'
        
        response = requests.get(f'http{"" if DEV_MODE else "s"}://{path}/did.json')
        return response.json()

    data = _via_http()
    # Assume Base 58 encoding due to DID:WEB specs; shortcut due to known doc
    public_key_58 = data['verificationMethod'][0]['publicKeyBase58']
    public_bytes = base58.b58decode(public_key_58)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    return public_key

def main(arg_list=None):
    args = parse_args(arg_list)
    with open(args.jwt_file) as f:
        jwt_text = f.read()

    public_key = get_public_key(args.host)
    try:
        decoded_text = jwt.decode(jwt_text, public_key, JWT_ALGORITHM)
    except InvalidSignatureError as ex:
        print('Token signature does not match')
    except DecodeError as ex:
        print('Token failed validation')
    except InvalidTokenError as ex:
        print('Invalid Token passed')
    else:
        print('Token validated successfully')

if __name__ == '__main__':
    main()
