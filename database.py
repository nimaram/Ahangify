from motor.motor_asyncio import AsyncIOMotorClient
from decouple import config
from schemas.models import UserSignUpSchema
from fastapi import HTTPException, status


MONGODB_URL = config('MONGODB_URL')

client = AsyncIOMotorClient(MONGODB_URL)

# database config
database = client.Ahangify
UsersCollection = database.Users
VerificationCode = database.VerificationCode

# check if there is a repeated username or email
async def check_repeated_username_or_email(user: UserSignUpSchema) -> bool | dict:
    user_via_email = await UsersCollection.find_one({
        "email": user.email
    })
    user_via_username = await UsersCollection.find_one({
        "username": user.username
    })
    if user_via_email or user_via_username: 
        raise HTTPException(detail="You use an email or username that's existed before.", status_code=status.HTTP_400_BAD_REQUEST)
    else:
        return False