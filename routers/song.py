from database import create_song
from fastapi import HTTPException, status, APIRouter, Depends
from typing import Annotated
from schemas.models import SongSchema


router = APIRouter()
