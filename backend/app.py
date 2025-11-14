from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
import shutil
import tempfile
import os
import io
import zipfile
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

app = FastAPI()

# Logging for diagnostics
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Serve static frontend
app.mount("/static", StaticFiles(directory="./static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200000

@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


@app.post("/encrypt")
async def encrypt(file: UploadFile = File(...), password: str = Form(...)):
    if not password:
        raise HTTPException(status_code=400, detail="Password required")

    # Read uploaded file into memory and compress into zip
    data = await file.read()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add logging to verify ZIP creation during encryption
        logger.info("Adding file to ZIP: %s", file.filename or "file")
        zf.writestr(file.filename or "file", data)

        # Ensure the file is added to the ZIP archive
        if not zip_buffer.getvalue():
            logger.error("ZIP archive is empty after adding file")
            raise HTTPException(status_code=500, detail="Failed to create ZIP archive during encryption")
    plain = zip_buffer.getvalue()

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plain, None)

    # file format: salt(16) + nonce(12) + ct
    out = salt + nonce + ct

    # Ensure the uploaded file has a valid name
    input_filename = file.filename or "uploaded_file"
    output_filename = input_filename + ".enc"

    # Write the encrypted file to a temporary location
    out_path = os.path.join(tempfile.gettempdir(), output_filename)
    with open(out_path, "wb") as f:
        f.write(out)

    # Return the encrypted file as a downloadable response with correct headers
    return FileResponse(
        out_path,
        filename=output_filename,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=\"{output_filename}\""}
    )


@app.post("/roundtrip")
async def roundtrip_test(content: bytes = File(...), password: str = Form(...)):
    """In-memory test endpoint: encrypt the provided bytes, then decrypt and verify round-trip.
    Returns JSON {ok: true} if decrypted bytes match original, otherwise raises 400 with diagnostic logged.
    This is for debugging only and does not write files to disk.
    """
    if not password:
        raise HTTPException(status_code=400, detail="Password required")

    # compress into zip in-memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("data", content)
    plain = zip_buffer.getvalue()

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plain, None)

    # simulate storage format
    stored = salt + nonce + ct

    # attempt to read back
    try:
        salt2 = stored[:SALT_SIZE]
        nonce2 = stored[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
        ct2 = stored[SALT_SIZE+NONCE_SIZE:]
        key2 = derive_key(password, salt2)
        aesgcm2 = AESGCM(key2)
        plain2 = aesgcm2.decrypt(nonce2, ct2, None)
    except Exception as e:
        logger.exception("Roundtrip decryption failed: %s", e)
        raise HTTPException(status_code=400, detail="Roundtrip decryption failed")

    if plain2 != plain:
        logger.error("Roundtrip mismatch: lengths %d vs %d", len(plain), len(plain2))
        raise HTTPException(status_code=400, detail="Roundtrip mismatch")

    return {"ok": True}


@app.post("/decrypt")
async def decrypt(file: UploadFile = File(...), password: str = Form(...)):
    if not password:
        raise HTTPException(status_code=400, detail="Password required")

    data = await file.read()
    if len(data) < SALT_SIZE + NONCE_SIZE + 1:
        raise HTTPException(status_code=400, detail="Invalid file")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ct = data[SALT_SIZE+NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plain = aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        # Log the exception for debugging while returning a generic error to clients
        logger.exception("Decryption failed: %s", str(e))
        raise HTTPException(status_code=400, detail="Decryption failed. Bad password or corrupted file.")

    # plain is a zip; extract first file to temp and return
    zip_buffer = io.BytesIO(plain)
    with zipfile.ZipFile(zip_buffer, 'r') as zf:
        namelist = zf.namelist()
        if not namelist:
            raise HTTPException(status_code=400, detail="Decrypted zip is empty")
        first = namelist[0]
        extracted = zf.read(first)

        # Add logging to verify ZIP contents during decryption
        logger.info("ZIP contents: %s", namelist)

        # Ensure the extracted file is valid
        if not extracted:
            logger.error("Extracted file is empty")
            raise HTTPException(status_code=400, detail="Decrypted file is empty")

    # Return the decrypted file directly as a downloadable response
    return HTMLResponse(
        content=extracted,
        headers={
            "Content-Disposition": f"attachment; filename=\"{os.path.basename(first)}\"",
            "Content-Type": "application/octet-stream"
        }
    )
