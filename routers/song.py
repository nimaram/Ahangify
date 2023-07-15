from models.models import Song
from database import create_song
from fastapi import HTTPException, status, APIRouter


router = APIRouter()

@router.post("/api/add-song", response_model=Song)
async def add_song(song: Song):
    response = await create_song(song.dict())
    if response: 
        return song
    raise HTTPException("Something went wrong.", status_code=status.HTTP_400_BAD_REQUEST)