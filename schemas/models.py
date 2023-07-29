from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Any
from datetime import datetime
from fastapi import Form, status
from pydantic import ValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException


# Account part 

class OTPSettings(BaseModel):
    otp_status: bool = False
    secret: str = ""


class UserSignUpSchema(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(title="Password", max_length=100, min_length=5)
    repeated_password: str = Field(title="RepeatedPassword", max_length=100, min_length=5)
    user_type: Optional[str] = Field("disabled", tile="UserType", max_length=10)
    permissions: Optional[list[str]] = ["users:general"]
    user_settings: Optional[dict] = {
        "otp_settings": Optional[OTPSettings]
    }
    created_at: Optional[datetime] = datetime.utcnow()


    @validator('repeated_password')
    def passwords_match(cls, value, values):
        if 'password' in values and value != values['password']:
            raise ValueError("Passwords do not match")
        return value


    class Config:
        scheme_extra = {
            "username": "John",
            "email": "John@email.com",
            "password": "123456",
            "user_type": "disabled"
        }


class UserDB(BaseModel):
    username: str
    email: str
    password: str
    user_type: str
    permissions: list
    user_settings: dict


class TokenPayload(BaseModel):
    account: str = None
    exp: int = None


class ConfirmCode(BaseModel):
    code: str
    user_email: EmailStr    


class TokenBlacklist(BaseModel):
    token: str = None
    exp: datetime = None    


class ResetPasswordRequest(BaseModel):
    email: EmailStr = Field()


class ResetPasswordTokens(BaseModel):
    reset_token: str
    email: EmailStr
    created_at: datetime 
    expired_at: datetime   


class ResetPasswordData(BaseModel):
    password: str
    repeated_password: str    

    # the below codes are disable cause the password and repeated one are gonna be checked \
    # in the endpoint
    # @validator("repeated_password")
    # def passwords_match(cls, value, values):
    #     if 'password' in values and value != values['password']:
    #         raise ValueError("Passwords do not match")
    #     return value


# core part
class SongSchema(BaseModel):
    title: str = Field(title="Your song's title")
    slug: Optional[str] = ""
    description: Optional[str | None] = Field(None, title="Description of the song")
    file_slug: Optional[str] = "" 
    duration: Optional[int] = 0
    listeners: Optional[int] = 0
    singer: Optional[list[str] | None] = None
    producer: Optional[list[str] | None] = None
    uploaded_by: Optional[Any] = "nobody!"
    created_at: Optional[datetime | None] = None
    

def checker(data: str = Form(...)):
    try:
        model = SongSchema.model_validate_json(data)
    except ValidationError as e:
        raise HTTPException(
            detail=jsonable_encoder(e.errors()),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    return model    