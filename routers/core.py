from fastapi import APIRouter


router = APIRouter()


@router.get("/", tags=["general"])
async def home() -> dict:
    return {"message": "Ahangify!"}