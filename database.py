from motor.motor_asyncio import AsyncIOMotorClient
from decouple import config
from schemas.models import UserSignUpSchema
from fastapi import HTTPException, status

MONGODB_URL = config('MONGODB_URL')

client = AsyncIOMotorClient(MONGODB_URL)

# database config
database = client.Ahangify
# SongCollection = database.Song
UsersCollection = database.Users


# async def create_song(song):
#     result = await SongCollection.insert_one(song)
#     return result

# check if there is a repeated username or email
async def check_repeated_username_or_email(user: UserSignUpSchema) -> bool | dict:
    user_via_email = await UsersCollection.find_one({
        "email": user.email
    })
    user_via_username = await UsersCollection.find_one({
        "username": user.username
    })
    if user_via_email or user_via_username: 
        raise HTTPException(detail="You use an email that's existed before.", status_code=status.HTTP_400_BAD_REQUEST)
    else:
        return False