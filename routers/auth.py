from fastapi import HTTPException, status, APIRouter, Body, Depends, Header
from schemas.models import UserSignUpSchema, UserDB
from database import UsersCollection, VerificationCode
from jose import jwt, JWTError
from auth.hash import get_password_hash
from typing import Annotated
from database import check_repeated_username_or_email, token_blacklist
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr
from auth.jwt_handler import (
    login_for_access_token,
    get_current_user,
    JWT_ALGORITHM,
    JWT_SECRET,
    TokenPayload,
    get_user,
    create_access_token,
    create_refresh_token
)
from fastapi_mail import MessageSchema, MessageType
from utils.code import give_code
from utils.mail import mail_service
from datetime import datetime
from typing import Optional
from fastapi.security import HTTPBearer
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from schemas.models import TokenBlacklist
from auth.jwt_handler import check_token_valid
from fastapi.responses import RedirectResponse

security = HTTPBearer()


router = APIRouter()


async def check_authentication(auth: Optional[str | None] = Header(alias="Authorization", default="")):
    try:
        jwt_token = auth.replace("Bearer ", "")
        payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("account")
        if email is None:
            return {"auth_status": False}        
        token_info = TokenPayload(**payload)
        if datetime.fromtimestamp(token_info.exp) < datetime.utcnow():
            return {"auth_status": False}
    except:
        return {"auth_status": False}            
    user = await get_user(email=email)
    if not user:
        return {"auth_status": False}            
    return {"auth_status": True}


@router.post("/api/sign-up", tags=["users"], status_code=status.HTTP_201_CREATED)
async def user_sign_up(msg: Annotated[dict, Depends(check_authentication)], user: Annotated[UserSignUpSchema, Body()] = None):
    if msg.get("auth_status") == True:
        return RedirectResponse("http://localhost:8000/")    
    check_point = await check_repeated_username_or_email(user)
    if check_point == False:
        plain_password = user.password     
        user.password = get_password_hash(user.password) 
        del(user.repeated_password)
        setattr(user, 'user_type', 'disabled')
        user_response = await UsersCollection.insert_one(user.model_dump())

        # send a verification email
        verification_code = give_code()
        message = MessageSchema(
            subject="کد تایید آهنگیفای",
            recipients=[f"{user.email}"],
            body=f"Code: {verification_code}",
            subtype=MessageType.html
        )
        data_code = {
            "code": str(verification_code),
            "account": user.email,
            "created_at": datetime.utcnow()
        }
        await VerificationCode.insert_one(data_code)
        await mail_service.send_message(message)

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


@router.post("/api/refresh-token", tags=["users"], status_code=status.HTTP_200_OK)
async def refresh_token(refresh_token: str = Body(...)):
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        token_data = TokenPayload(**payload)
    except JWTError:
        raise HTTPException(detail="Invalid token", status_code=status.HTTP_403_FORBIDDEN) 
    user = await get_user(email=token_data.account)
    if not user:
        raise HTTPException(detail="Invalid token for user", status_code=status.HTTP_404_NOT_FOUND)
    return {
        "access_token": create_access_token({"account": user.email}),
        "refresh_token": create_refresh_token({"account": user.email})
    }

@router.get("/api/get-user-type", tags=["users"], status_code=status.HTTP_200_OK, summary="This api returns account's type")
async def get_user_type(current_user: Annotated[UserDB, Depends(get_current_user)]):
    return current_user.user_type


@router.post("/api/confirm-account-via-code", tags=["users"], status_code=status.HTTP_202_ACCEPTED)
async def confirm_account(code: Annotated[str, Body()], current_user: Annotated[UserDB, Depends(get_current_user)]):
    if type(current_user) != True | UserDB:
        return RedirectResponse("http://localhost:8000/api/sign-in")
    verification_code = await VerificationCode.find_one({"account": current_user.email})
    if not verification_code:
        raise HTTPException(detail="You came up with a wrong URL!", status_code=status.HTTP_404_NOT_FOUND)
    elif verification_code["code"] == code:
        await UsersCollection.update_one({"email": current_user.email}, {"$set": {"user_type": "normal"}})
        await VerificationCode.delete_one({"account": current_user.email})
        return {
            "message": "Your account has been verified successfully!"
        }
    elif verification_code["code"] != code:
        raise HTTPException(detail="Code is wrong!", status_code=status.HTTP_400_BAD_REQUEST)

@router.post("/api/sign-out", tags=["users"], status_code=status.HTTP_204_NO_CONTENT)
async def sign_out_user(base: HTTPAuthorizationCredentials= Depends(security)):
    token = base.credentials
    check_res = await check_token_valid(token)
    if check_res != True:
         return RedirectResponse("http://localhost:8000/api/sign-in")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("account")
        if email is None:
            raise HTTPException(detail="Could not validate credentials", status_code=status.HTTP_401_UNAUTHORIZED)
        token_data = TokenPayload(**payload)

        if datetime.fromtimestamp(token_data.exp) < datetime.utcnow():
            raise HTTPException(detail="Token expired", status_code=status.HTTP_401_UNAUTHORIZED)      
    except:
        raise HTTPException(detail="Not authenticated", status_code=status.HTTP_401_UNAUTHORIZED)
    user = await get_user(email=email)
    if not user:
        raise HTTPException(detail="User not found", status_code=status.HTTP_404_NOT_FOUND)
    data = TokenBlacklist(token=token, exp=payload.get("exp"))
    token_exists = await token_blacklist.find_one({"token": token})
    print(token_exists)
    if token_exists:
        raise HTTPException(detail="Something went wrong", status_code=status.HTTP_400_BAD_REQUEST)

    await token_blacklist.insert_one(data.model_dump())


# TODO: Delete unused verification codes after 10 minutes and lots of things... 
# TODO: Reset password endpoint
# TODO: Passkeys       