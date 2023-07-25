from fastapi import HTTPException, status, APIRouter, Body, Depends, Header, Path, Query
from schemas.models import(
     UserSignUpSchema,
     UserDB,
     TokenBlacklist,
     ResetPasswordTokens,
     ResetPasswordRequest,
     ResetPasswordData
    )
from database import UsersCollection, VerificationCode, reset_password_tokens, check_repeated_username_or_email, token_blacklist
from jose import jwt, JWTError
from auth.hash import get_password_hash
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
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
from datetime import datetime,  timedelta
from typing import Optional
from fastapi.security import HTTPBearer
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from auth.jwt_handler import check_token_valid
from fastapi.responses import RedirectResponse
import uuid
import secrets
import pyotp
import qrcode
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from qrcode.image.styledpil import StyledPilImage
import io
from fastapi.responses import StreamingResponse
from fastapi.background import BackgroundTasks 
from pydantic import Field
import base64
import string
import secrets


alphabet = string.ascii_letters + string.digits
security = HTTPBearer()

router = APIRouter()

# built-in fuctions
async def is_otp_correct(otp: int, secret: str):
    sec_n = base64.b32encode(f"{secret}".encode('ascii'))
    tk = pyotp.TOTP(sec_n)
    return tk.verify(otp)



@router.get("/api/generate-otp", tags=["users"])
async def generate_otp_code(background_tasks: BackgroundTasks, user: UserDB = Depends(get_current_user)):
    user_set = user.user_settings.get("otp_settings")
    chck = user_set["otp_status"]
    if chck == False:
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_302_FOUND)
    else:
        sec = user_set["secret"]
        sec_n = base64.b32encode(f"{sec}".encode('ascii'))
        totp = pyotp.TOTP(sec_n)
        qr_code = qrcode.QRCode()
        qr_code.add_data(totp.provisioning_uri(name=user.email, issuer_name="Ahangify"))
        qr_code.make(fit=True)
        img = qr_code.make_image(image_factory=StyledPilImage, module_drawer=RoundedModuleDrawer(), color_mask=RadialGradiantColorMask((255,255,255), (50,179,205), (13,234,65)))
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        background_tasks.add_task(buf.close)
        return StreamingResponse(buf, media_type="image/png")

async def check_authentication(auth: Optional[str | None] = Header(alias="Authorization", default="", title="Auth key", description="Do not enter anything in swagger!")):
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
async def user_sign_up(msg: Annotated[dict, Depends(check_authentication)], background_tasks: BackgroundTasks, user: Annotated[UserSignUpSchema, Body()] = None):
    if msg.get("auth_status") == True:
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_302_FOUND)    
    check_point = await check_repeated_username_or_email(user)
    if check_point == False:
        plain_password = user.password     
        user.password = get_password_hash(user.password) 
        del(user.repeated_password)
        setattr(user, 'user_type', 'disabled')
        user.user_settings["otp_settings"] = {"otp_status": False, "secret": f"{''.join(secrets.choice(alphabet) for i in range(12))}"}
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
        background_tasks.add_task(mail_service.send_message, message)

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
async def user_sign_in(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], code: Annotated[int | None, Body()] = None):
    data = {
        "username": form_data.username,
        "password": form_data.password
    }
    user = await get_user(email=form_data.username)
    check = user.user_settings.get("otp_settings")
    if check["otp_status"] == True:
        user_secret = check["secret"]
        if not code:
            raise HTTPException(detail="2FA code needed.", status_code=status.HTTP_400_BAD_REQUEST)
        elif not await is_otp_correct(int(code), user_secret):
            raise HTTPException(detail="You've send an wrong otp!", status_code=status.HTTP_400_BAD_REQUEST)
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
    if current_user.user_type != "disabled":
        return RedirectResponse("http://localhost:8000/api/sign-in", status_code=status.HTTP_302_FOUND)
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
         return RedirectResponse("http://localhost:8000/api/sign-in", status_code=status.HTTP_302_FOUND)
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


@router.post("/api/forgot-password", tags=["users"], status_code=status.HTTP_200_OK)
async def reset_password_account(check: Annotated[dict, Depends(check_authentication)], v: Annotated[ResetPasswordRequest, Body()]):
    if check.get("auth_status") == True:
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_302_FOUND)  
    user = await get_user(email=v.email)
    if not user:
        raise HTTPException(detail="User not found", status_code=status.HTTP_400_BAD_REQUEST)
    reset_token = uuid.uuid1()
    data = ResetPasswordTokens(reset_token=str(reset_token), email=user.email, created_at=datetime.utcnow(),
                               expired_at=datetime.utcnow() + timedelta(minutes=10))
    chck = await reset_password_tokens.find_one({"email": user.email})
    if chck and chck.get("expired_at") >= datetime.utcnow():
        raise HTTPException(detail="You already requested a reset password link!", status_code=status.HTTP_400_BAD_REQUEST)
    await reset_password_tokens.insert_one(data.model_dump())

     # send a reset password link email

    message = MessageSchema(
            subject="تعویض رمز عبور در آهنگیفای",
            recipients=[f"{user.email}"],
            body=f"link: http://localhost:8000/reset-password/{reset_token}",
            subtype=MessageType.html
        )
    await mail_service.send_message(message)

    return {
        "message": "Reset password link sent successfully to your email!"
    }


@router.patch("/api/reset-password/{uid}", tags=["users"], status_code=status.HTTP_202_ACCEPTED)
async def update_user_password(check: Annotated[dict, Depends(check_authentication)], uid: Annotated[str, Path()], data: Optional[ResetPasswordData]):
    if check.get("auth_status") == True:
        return RedirectResponse("http://localhost:8000/", status_code=status.HTTP_303_SEE_OTHER)    
    reset_token = await reset_password_tokens.find_one({"reset_token": uid})
    if reset_token:
        if reset_token.get("expired_at") <= datetime.utcnow():
            raise HTTPException(detail="Token is expired or invalid!", status_code=status.HTTP_400_BAD_REQUEST)
        else:
            if data.password == data.repeated_password:
                hashed_password = get_password_hash(data.password)
                await UsersCollection.update_one({"email": reset_token.get("email")}, {"$set": {"password": hashed_password}})
                await reset_password_tokens.delete_one({"reset_token": uid})
                message = MessageSchema(
                 subject="رمز شما با موفقیت عوض شد!",
                 recipients=[f"{reset_token.get('email')}"],
                 body="",
                 subtype=MessageType.html
                )
                await mail_service.send_message(message)
                return {
                    "message": "You've changed your password successfully!"
                }
            else:
                raise HTTPException(detail="Passwords do not match!", status_code=status.HTTP_400_BAD_REQUEST)
    else:
        raise HTTPException(detail="Not Found!", status_code=status.HTTP_404_NOT_FOUND)    


# TODO: Delete unused verification codes after 10 minutes and lots of things... 
# TODO: Passkeys 
# TODO: Make codes look prettier
# TODO: Add Google Oauth  