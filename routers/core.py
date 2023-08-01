from fastapi import APIRouter, Depends, status, UploadFile, File, BackgroundTasks, WebSocket
from auth.jwt_handler import PermissionChecker
from schemas.models import UserDB, SongSchema, checker
from fastapi.responses import RedirectResponse
from typing import Annotated
from database import Song, UsersCollection
from decouple import config
import io, logging
import uuid
import base64
import string, secrets
from mutagen.wave import WAVE
import aiofiles
import os
from datetime import datetime
from bson.dbref import DBRef
from fastapi.responses import StreamingResponse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import math
import wave


# basic app
router = APIRouter()



@router.get("/", tags=["artist_panel"])
async def home() -> dict:
    """
    Home page...
    """
    return {"message": "Ahangify!"}




@router.post("/api/publish-single", tags=["artist_panel"], status_code=status.HTTP_201_CREATED)
async def publish_new_song(background_tasks: BackgroundTasks, data: Annotated[SongSchema, Depends(checker)], file: UploadFile = File(title="WAV File") , user: UserDB = Depends(PermissionChecker(required_permissions=["song:write"]))):
    if user.user_type != "artist":
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_302_FOUND)
    else:
        unique_uuid = uuid.uuid1()
        whole_string = f"{str(unique_uuid)[:12]}{data.title}"
        unique_encoded_slug = base64.b64encode(bytes(whole_string, encoding="utf8"))
        file_name = f"{''.join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(24))}"  
        os.chdir(config("DLL_AUDIO_FILES"))
        file_bytes = await file.read()
        
        KEY = bytes(config("AES_KEY"), "utf-8").decode("unicode_escape").encode('latin-1')
        IV = bytes(config("AES_IV"), "utf-8").decode("unicode_escape").encode('latin-1')
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padding_length = 16 - (len(file_bytes) % 16)
        padded_bytes = file_bytes + bytes([padding_length] * padding_length)
        encrypted_data = cipher.encrypt(padded_bytes)
        
        async with aiofiles.open(f'{os.path.join(f"{file_name}.enc")}', mode="wb") as f:
            await f.write(IV)
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
async def publish_album():
    pass


@router.websocket("/api/stream-chunk/{uid}")
async def stream_audio(websocket: WebSocket, uid: str):
    if not uid:
        raise ValueError("I need uid!")
    else:
        await websocket.accept()
        KEY = bytes(config("AES_KEY"), "utf-8").decode("unicode_escape").encode('latin-1')
        IV = bytes(config("AES_IV"), "utf-8").decode("unicode_escape").encode('latin-1')
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        track = await Song.find_one({"slug": uid})
        try:
            os.chdir(config("DLL_AUDIO_FILES"))
        except:
            pass    
        decrypted_bytes = bytearray()
        async with aiofiles.open(f"{track.get('file_slug')}.enc", "rb") as f:
            iv = await f.read(16)
            cipher.iv = iv
            while True:
                block = await f.read(16)
                if not block:
                    break

                decrypted_block = cipher.decrypt(block)
                decrypted_bytes.extend(decrypted_block)
        padding_length = decrypted_bytes[-1]
        decrypted_bytes = decrypted_bytes[:-padding_length]            

    

        while True:
        # Read a chunk of bytes from the decrypted audio bytes
            chunk = decrypted_bytes[:1024]
            decrypted_bytes = decrypted_bytes[1024:]

            if not chunk:
                break


            # Send the chunk over the WebSocket
            
            await websocket.send_bytes(chunk)
           
        await websocket.close()


