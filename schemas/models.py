from pydantic import BaseModel, Field, EmailStr, validator
from fastapi import Path
from typing import Optional

# Song part 

class SongSchema(BaseModel):
    title: str
    slug: str
    description: Optional[str | None] = Field(None, title="Description of the song")
    file: str
    duration: float = Path(gt=0, title="Duration")
    listeners: int = Path(ge=0, title="Listeners")
    singer: list = []
    producer: Optional[list | None] = None
    uploaded_by: Optional[str]

class AlbumSchema(BaseModel):
    name: str
    description: Optional[str | None] = Field(None, title="Description of the album")
    cover: str
    songs: list = []
    singer: str


# Account part 
class UserSignUpSchema(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(title="Password", max_length=100, min_length=5)
    repeated_password: str = Field(title="RepeatedPassword", max_length=100, min_length=5)
    user_type: Optional[str] = Field("normal", tile="UserType", max_length=10)

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
            "user_type": "normal"
        }


class UserDB(BaseModel):
    username: str
    email: str
    password: str
    user_type: str


class TokenPayload(BaseModel):
    account: str = None
    exp: int = None


class ConfirmCode(BaseModel):
    code: str
    user_email: EmailStr    


class TokenBlacklist(BaseModel):
    token: str = None
    exp: int = None    