# Laboratory 6 — RSA and AES
Python 3.12 recommended. Run from project root.

```powershell
python -m pip install -r requirements.txt
python -m pytest -v
python -m uvicorn server.main:app --port 8000
```
In a second terminal: `python client.py`. Swagger: http://127.0.0.1:8000/docs.
Docker: `docker build -t lab6 .` then `docker run --rm -p 8000:8000 lab6` (stop local Uvicorn first).
RSA-OAEP SHA-256, AES-256-GCM. The session IV is combined with a fresh random 96-bit value per message to avoid fixed nonce reuse. This educational HTTP protocol does not authenticate the server public key or prevent replay; use TLS for real systems. Keys and sessions disappear on restart. Run one server worker.
