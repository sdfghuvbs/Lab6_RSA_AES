import json
import uuid
import os
import requests
from shared.crypto import RsaService, AesService

URL = os.getenv('API_URL', 'http://127.0.0.1:8000')

def exchange(message):
    rsa, aes = RsaService(), AesService()
    response = requests.get(URL + '/api/crypto-keys/random', timeout=10)
    response.raise_for_status()
    rsa_id = response.headers['x-rsa-id']
    key = aes.generate_secret_key()
    sid = uuid.uuid4().hex
    payload = json.dumps({'session_id': sid, 'key': key.key, 'iv': key.iv}, separators=(',', ':'))
    encrypted = rsa.encrypt(response.json(), payload)
    response = requests.post(URL + '/api/sessions', json={'ciphertext': encrypted}, headers={'x-rsa-id': rsa_id}, timeout=10)
    response.raise_for_status()
    cipher = aes.encrypt(key, message)
    print('RSA ID:', rsa_id, '\nSession ID:', sid, '\nEncrypted request:', cipher)
    response = requests.post(URL + '/api/messages', json={'ciphertext': cipher}, headers={'x-session-id': sid}, timeout=10)
    response.raise_for_status()
    print('Encrypted response:', response.json()['ciphertext'])
    print('Decrypted response:', aes.decrypt(key, response.json()['ciphertext']))

if __name__ == '__main__':
    while True:
        try:
            message = input('Enter message (exit to quit): ')
            if message.lower() == 'exit': break
            exchange(message)
        except (EOFError, KeyboardInterrupt): break
        except requests.RequestException as e: print('HTTP error:', e)
