from fastapi import HTTPException, status, APIRouter, Body, Depends
from schemas.models import UserSignUpSchema, UserDB
from database import UsersCollection
from auth.hash import get_password_hash
from typing import Annotated
from database import check_repeated_username_or_email
from fastapi.security import OAuth2PasswordRequestForm
from auth.jwt_handler import (
    login_for_access_token,
    get_current_user
)


router = APIRouter()

@router.post("/api/sign-up", tags=["users"], status_code=status.HTTP_201_CREATED)
async def user_sign_up(user: UserSignUpSchema = Body(default=None)):
    check_point = await check_repeated_username_or_email(user)
    if check_point == False:
        plain_password = user.password     
        user.password = get_password_hash(user.password) 
        del(user.repeated_password)
        setattr(user, 'user_type', 'normal')
        user_response = await UsersCollection.insert_one(user.dict())
        if user_response:
            data = {
                "username": user.email,
                "password": plain_password
            }
            del(plain_password)
            response = await login_for_access_token(data)
            return response
        else:
            raise HTTPException("Something went wrong.", status_code=status.HTTP_400_BAD_REQUEST)
        


@router.post("/api/sign-in", tags=["users"], status_code=status.HTTP_200_OK)
async def user_sign_in(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    data = {
        "username": form_data.username,
        "password": form_data.password
    }
    response = await login_for_access_token(form_data=data)
    return response


@router.get("/api/test-token", tags=["users"], status_code=status.HTTP_200_OK)
async def test_token(current_user: Annotated[UserDB, Depends(get_current_user)]):
    return current_user.email