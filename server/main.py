import json
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel
from shared.crypto import RsaService, AesService, AesKey, raw

rsa = RsaService()
aes = AesService()
keys = {}
sessions = {}

@asynccontextmanager
async def lifespan(app):
    keys.clear(); sessions.clear()
    for i in range(1, 11): keys[i] = rsa.generate_crypto_keys()
    yield

app = FastAPI(title='Lab 6 - Encrypted communication', lifespan=lifespan)

class Cipher(BaseModel):
    ciphertext: str

@app.post('/api/crypto-keys/generate/rsa-keys', response_model=int)
async def generate():
    try:
        pair = rsa.generate_crypto_keys()
        i = max(keys, default=0) + 1
        keys[i] = pair
        return i
    except Exception as e:
        raise HTTPException(400, 'RSA generation failed') from e

@app.get('/api/crypto-keys/rsa-public-key/{id}', response_model=str)
async def public_key(id: int):
    if id not in keys: raise HTTPException(404, 'RSA key not found')
    return keys[id].public_key

@app.get('/api/crypto-keys/random', response_model=str)
async def random_key(response: Response):
    i = secrets.choice(list(keys))
    response.headers['x-rsa-id'] = str(i)
    return keys[i].public_key

@app.post('/api/sessions')
async def create_session(body: Cipher, x_rsa_id: int = Header(...)):
    if x_rsa_id not in keys: raise HTTPException(404, 'RSA key not found')
    try:
        data = json.loads(rsa.decrypt(keys[x_rsa_id].private_key, body.ciphertext))
        sid = data['session_id']
        key = AesKey(data['key'], data['iv'])
        if not isinstance(sid, str) or not sid or len(raw(key.key)) != 32 or len(raw(key.iv)) != 12: raise ValueError()
    except Exception as e: raise HTTPException(400, 'Invalid session data') from e
    if sid in sessions: raise HTTPException(409, 'Session already exists')
    sessions[sid] = key
    return {'status': 'created', 'session_id': sid}

@app.post('/api/messages', response_model=Cipher)
async def message(body: Cipher, x_session_id: str = Header(...)):
    if x_session_id not in sessions: raise HTTPException(404, 'Session not found')
    key = sessions[x_session_id]
    try: plain = aes.decrypt(key, body.ciphertext)
    except Exception as e: raise HTTPException(400, 'Invalid encrypted message') from e
    reply = f'{plain}. Received: {datetime.now(timezone.utc).isoformat()}'
    return Cipher(ciphertext=aes.encrypt(key, reply))
