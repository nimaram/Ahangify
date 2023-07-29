from fastapi import APIRouter, Depends, status, Form, UploadFile, File, BackgroundTasks
from auth.jwt_handler import PermissionChecker
from schemas.models import UserDB, SongSchema, checker
from fastapi.responses import RedirectResponse
from typing import Annotated
from database import Song, UsersCollection
import uuid
import base64
import string, secrets
import shutil
from mutagen.wave import WAVE
import aiofiles
import os
from datetime import datetime
from bson.dbref import DBRef

# basic app
router = APIRouter()





@router.get("/", tags=["artist_panel"])
async def home() -> dict:
    """
    Home page...
    """
    return {"message": "Ahangify!"}




@router.post("/api/publish", tags=["artist_panel"])
async def publish_new_song(background_tasks: BackgroundTasks, data: Annotated[SongSchema, Depends(checker)], file: UploadFile = File(title="WAV File") , user: UserDB = Depends(PermissionChecker(required_permissions=["song:write"]))):
    if user.user_type != "artist":
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_302_FOUND)
    else:
        unique_uuid = uuid.uuid1()
        whole_string = f"{str(unique_uuid)[:12]}{data.title}"
        unique_encoded_slug = base64.b64encode(bytes(whole_string, encoding="utf8"))
        file_name = f"{''.join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(24))}"  
        os.chdir("dll_app_storage")
        async with aiofiles.open(f'{os.path.join(f"{file_name}.wav")}', mode="wb") as f:
            content = await file.read()
            await f.write(content)
        track = WAVE(f"{file_name}.wav")
        track_info = track.info
        duration = int(track_info.length)
        data.slug = str(unique_encoded_slug.decode("utf-8")[:4])+"".join(secrets.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(18))
        data.file_slug = f"{file_name}"
        data.duration = duration
        user_p = await UsersCollection.find_one({"email": user.email})
        data.uploaded_by = DBRef("User", user_p.get("_id"))
        data.singer = [user.username]
        data.created_at = datetime.utcnow()
        await Song.insert_one(data.model_dump())
