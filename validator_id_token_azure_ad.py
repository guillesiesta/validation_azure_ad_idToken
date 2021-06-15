import jwt
import requests

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


PEMSTART = '-----BEGIN CERTIFICATE-----\n'
PEMEND = '\n-----END CERTIFICATE-----\n'

def decode_azure_ad_id_token_without_publick_key(token):
    decoded = jwt.decode(token, verify=False)

    '''for key in decoded.keys():
        print(key + ': ' + str(decoded[key]))'''

    return decoded

    # get Microsoft Azure public key
def get_public_key_for_azure_ad_token_by_kid(kid):
    response = requests.get(
    'https://login.microsoftonline.com/common/.well-known/openid-configuration',
    ).json()

    jwt_uri = response['jwks_uri']
    response_keys = requests.get(jwt_uri).json()
    pubkeys = response_keys['keys']

    public_key = ''

    for key in pubkeys:
        # found the key that matching the kid in the token header
        if key['kid'] == kid:
            # construct the public key object
            mspubkey = str(key['x5c'][0])
            cert_str = PEMSTART + mspubkey + PEMEND
            #logger.debug(cert_str)
            cert_obj = load_pem_x509_certificate(cert_str.encode(), default_backend())
            public_key = cert_obj.public_key()

    return public_key


# decode the given Azure AD access token
# the aud value is the Application (client) ID
def azure_ad_id_token_decoder(token,aud):
    try:
        header = jwt.get_unverified_header(token)
        public_key = get_public_key_for_azure_ad_token_by_kid(header['kid'])
        #logger.debug(access_token)
        decoded = jwt.decode(token, key=public_key, algorithms='RS256', audience=aud)
    except ValueError as error:  # Usually caused by CSRF
        pass

    '''for key in decoded.keys():
        print(key + ': ' + str(decoded[key]))'''

    return decoded
