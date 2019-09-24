import base64
import json
import re
import hmac
import hashlib
import uuid
import datetime
import time

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def sign(payload: dict, secret: str, options: dict = None) -> str:
    if payload is None:
        raise TypeError('Invalid payload')
    if secret is None:
        raise TypeError('Invalid secret')

    now = int(time.time()) # seconds since epoch
    options = options or {}
    header = {}
    header['alg'] = options.get('algorithm', 'HS256')
    header['typ'] = 'JWT'
    payload['jti'] = options.get('jwt-id', str(uuid.uuid4()))
    payload['iat'] = options.get('issued-at', now)
    payload['exp'] = options.get('expires-in', (now+120*1000)) # milliseconds
    payload['nbf'] = options.get('not-before', now) # milliseconds
    
    if payload['nbf'] < now:
        raise ValueError('Invalid value for claim: not-before')
    if payload['nbf'] >= payload['exp']:
        raise ValueError('Invalid value for claim: not-before')

    # sort claims by name (ascending)
    payload = dict(sorted(payload.items()))

    b64_header = enc_base64(to_json(header))
    b64_payload = enc_base64(to_json(payload))
    token = f'{b64_header}.{b64_payload}'
    signature = hash[header['alg']].sign(token, secret)

    return f'{token}.{signature}'


def verify(signed_token: str, secret: str) -> dict:
    if signed_token is None:
        raise TypeError('Invalid signed token')
    if secret is None:
        raise TypeError('Invalid secret')
    m = re.match(
        r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+$', signed_token)
    if not m:
        raise ValueError('Invalid jwt token')

    b64_header, b64_payload, b64_signature = signed_token.split('.', 2)
    header = to_dict(dec_base64(b64_header))
    payload = to_dict(dec_base64(b64_payload))

    now = int(time.time()) # seconds since epoch
    not_before = payload['nbf']
    expires_in = payload['exp']

    if now < not_before or now > expires_in:
        raise InvalidTokenError('The token is expired')

    signature = hash[header['alg']].verify(
        f'{b64_header}.{b64_payload}', secret, b64_signature)

    return payload


def to_json(obj):
    return json.dumps(obj, separators=(',', ':'))


def to_dict(json_obj):
    return json.loads(json_obj)


def to_datetime(milliseconds, default=None):
    return datetime.datetime.fromtimestamp()


def enc_base64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded_bytes = base64.urlsafe_b64encode(data)
    return encoded_bytes.decode('utf-8').replace('=', '')


def dec_base64(data):
    missing_padding = len(data) % 4
    if missing_padding:
        if isinstance(data, bytes):
            data += b'=' * (4 - missing_padding)
        if isinstance(data, str):
            data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)


class HMAC():
    def sign(self, message, secret):
        return self._hash(message, secret)

    def verify(self, message, secret, signature):
        if signature != self._hash(message, secret):
            raise InvalidSignatureError('The signature is not authentic')

    def _hash(self, message, secret):
        hmac_ = hmac.new(secret.encode('utf-8'),
                         message.encode('utf-8'), 
                         hashlib.sha256)
        h = hmac_.digest()
        return enc_base64(h)


class RSASSA():
    def sign(self, message, secret):
        key = RSA.importKey(secret)
        h = self._hash(message, secret)
        signature = pkcs1_15.new(key).sign(h)
        return enc_base64(signature)

    def verify(self, message, secret, signature):
        key = RSA.importKey(secret)
        h = self._hash(message, secret)
        try:
            pkcs1_15.new(key).verify(h, dec_base64(signature))
        except (ValueError, TypeError):
            raise InvalidSignatureError('The signature is not authentic')

    def _hash(self, message, secret):
        return SHA256.new(message.encode('utf-8'))


class InvalidSignatureError(Exception):
    pass

class InvalidTokenError(Exception):
    pass

hash = {
    'HS256': HMAC(),
    'RS256': RSASSA()
}
