from fastapi import FastAPI, HTTPException, status
from music.models import Song
from fastapi.middleware.cors import CORSMiddleware
from config import (
    create_song
)

# App object
app = FastAPI()

origins = ["https://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

@app.post("/api/add-song", response_model=Song)
async def add_song(song: Song):
    response = await create_song(song.dict())
    if response: 
        return song
    raise HTTPException("Something went wrong.", status_code=status.HTTP_400_BAD_REQUEST)