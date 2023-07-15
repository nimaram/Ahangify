from pydantic import BaseModel, Field
from fastapi import Path
from typing import Optional

class Song(BaseModel):
    title: str
    description: Optional[str | None] = Field(None, title="Description of the song")
    file: str
    duration: float = Path(gt=0, title="Duration")
    listeners: int = Path(ge=0, title="Listeners")
    singer: list = []
    producer: Optional[list | None] = None

class Album(BaseModel):
    name: str
    description: Optional[str | None] = Field(None, title="Description of the album")
    cover: str
    songs: list = []
    singer: str

