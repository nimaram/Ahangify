from fastapi import HTTPException, status, APIRouter, Body
from schemas.models import UserSignUpSchema
from database import UsersCollection
from auth.hash import get_password_hash
from database import check_repeated_username_or_email

router = APIRouter()

@router.post("/api/sign-up", tags=["users"], status_code=status.HTTP_201_CREATED)
async def user_sign_up(user: UserSignUpSchema = Body(default=None)):
    check_point = await check_repeated_username_or_email(user)
    if check_point == False:     
        user.password = get_password_hash(user.password) 
        del(user.repeated_password)
        setattr(user, 'user_type', 'normal')
        user_response = await UsersCollection.insert_one(user.dict())
        if user_response:
            return user.email
        else:
            raise HTTPException("Something went wrong.", status_code=status.HTTP_400_BAD_REQUEST)