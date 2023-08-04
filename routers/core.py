from fastapi import APIRouter, Depends, status, UploadFile, File, HTTPException, Header
from fastapi.responses import StreamingResponse
from auth.jwt_handler import PermissionChecker
from schemas.models import UserDB, SongSchema, checker
from fastapi.responses import RedirectResponse
from typing import Annotated
from database import Song, UsersCollection
from decouple import config
import io
import uuid
import base64
import string, secrets
import aiofiles
import os
from datetime import datetime
from bson.dbref import DBRef
from Cryptodome.Cipher import ChaCha20
import math
import wave
import re
# basic app
router = APIRouter()



@router.get("/", tags=["artist_panel"])
async def home() -> dict:
    """
    Home page...
    """
    return {"message": "Ahangify!"}




@router.post("/api/publish-single", tags=["artist_panel"], status_code=status.HTTP_201_CREATED)
async def publish_new_song(data: Annotated[SongSchema, Depends(checker)], file: UploadFile = File(title="WAV File") , user: UserDB = Depends(PermissionChecker(required_permissions=["song:write"]))):
    if user.user_type != "artist":
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_302_FOUND)
    else:
        unique_uuid = uuid.uuid1()
        whole_string = f"{str(unique_uuid)[:12]}{data.title}"
        unique_encoded_slug = base64.b64encode(bytes(whole_string, encoding="utf8"))
        file_name = f"{''.join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(24))}"  
        try:
            os.chdir(config("DLL_AUDIO_FILES"))
        except:
            pass    
        file_bytes = await file.read()
        KEY = bytes(config("CHA_KEY"), "utf-8").decode("unicode_escape").encode('latin-1')
        NONCE = bytes(config("CHA_NONCE"), "utf-8").decode("unicode_escape").encode('latin-1')
        cipher = ChaCha20.new(key=KEY, nonce=NONCE)
        encrypted_data = cipher.encrypt(file_bytes)
        async with aiofiles.open(f'{os.path.join(f"{file_name}.enc")}', mode="wb") as f:
            await f.write(encrypted_data) 
        with io.BytesIO(file_bytes) as wav_buffer:
            with wave.open(wav_buffer, "rb") as wave_file:
                frames = wave_file.getnframes()
                frame_rate = wave_file.getframerate()
                duration = frames / float(frame_rate)
                data.slug = str(unique_encoded_slug.decode("utf-8")[:4])+"".join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(17))
                data.file_slug = f"{file_name}"
                data.duration = math.floor(duration)
                user_p = await UsersCollection.find_one({"email": user.email})
                data.uploaded_by = DBRef("User", user_p.get("_id"))
                data.singer = [user.username]
                data.created_at = datetime.utcnow()
                await Song.insert_one(data.model_dump()) 
              
        return {
            "message": "Your track uploaded successfully!",
            "url": f"http://localhost:8000/track/{data.slug}"
        }
    

@router.post("/api/publish", tags=["artist_panel"])
async def publish_album(user: UserDB = Depends(PermissionChecker(required_permissions=["song:write"]))):
    pass


@router.get("/api/stream-chunk/{uid}")
async def stream_audio(uid: str, bytes_range: str = Header(None, description="Well, Swagger has some problems with headers, so test this endpoint in Postman")):
    if not uid:
        raise ValueError("I need uid!")

    track = await Song.find_one({"slug": uid})

    try:
        os.chdir(config("DLL_AUDIO_FILES"))
    except:
        pass

    chunk_filename = f"{track.get('file_slug')}.enc"
    KEY = bytes(config("CHA_KEY"), "utf-8").decode("unicode_escape").encode('latin-1')
    NONCE = bytes(config("CHA_NONCE"), "utf-8").decode("unicode_escape").encode('latin-1')
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)

    if bytes_range:
        range_match = re.match(r"bytes=(\d+)-(\d+)?", bytes_range)
        if range_match:
            start_byte = int(range_match.group(1))
            end_byte = int(range_match.group(2)) if range_match.group(2) else None
        else:
            raise HTTPException(status_code=416, detail="Invalid Range header")
    else:
        start_byte = 0
        end_byte = None

    async def audio_generator():
        async with aiofiles.open(chunk_filename, "rb") as file:
            if start_byte:
                await file.seek(start_byte)

            remaining_bytes = end_byte - start_byte if end_byte else None

            while remaining_bytes is None or remaining_bytes > 0:
                chunk_size = 4096 if remaining_bytes is None or remaining_bytes >= 4096 else remaining_bytes
                chunk = await file.read(chunk_size)

                if not chunk:
                    break

                decrypted_chunk = cipher.decrypt(chunk)
                yield decrypted_chunk

                if remaining_bytes:
                    remaining_bytes -= chunk_size

    if end_byte is not None and end_byte < start_byte:
        raise HTTPException(status_code=400, detail="Invalid byte range")

    headers = {}
    if start_byte or end_byte:
        file_size = os.path.getsize(chunk_filename)
        decrypted_file_size = int(file_size / cipher.block_size) * cipher.block_size
        headers["Content-Range"] = f"bytes {start_byte}-{end_byte}/{decrypted_file_size}"
        headers["Content-Length"] = str(end_byte - start_byte) if end_byte else str(decrypted_file_size - start_byte)

    return StreamingResponse(audio_generator(), media_type="audio/wav", headers=headers, status_code=status.HTTP_206_PARTIAL_CONTENT)