from datetime import timedelta, datetime
from decouple import config
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from fastapi import Depends, HTTPException, status
from database import UsersCollection, token_blacklist
from schemas.models import UserDB
from .hash import verify_password
from schemas.models import TokenPayload
from datetime import datetime
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_SECRET = config("SECRET_KEY")
JWT_ALGORITHM = config("JWT_ALGORITHM")
oauth2_scheme = OAuth2PasswordBearer(
     tokenUrl="/api/sign-in",
     scheme_name="user_login_schema"
)


security = HTTPBearer()


async def check_token_valid(token: str):
    """
    Checks if the token was blacklisted before or not
    """
    check_token = await token_blacklist.find_one({"token": token})
    if check_token:
        return False
    return True


def create_access_token(data: dict, expires: timedelta | None = None) -> str:
    """
    Creates access token for the user
    """
    to_encode = data.copy()
    if expires:
        expire = datetime.utcnow() + expires
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires: timedelta | None = None) -> str:
    """
    Creates refresh token for the user
    """
    to_encode = data.copy()
    if expires:
        expire = datetime.utcnow() + expires
    else:
        expire = datetime.utcnow() + timedelta(minutes=50)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt
    


async def get_user(email: str):
    """
    Gets the user's instance with the given email
    """
    user = await UsersCollection.find_one({"email": email})
    if user:
        return UserDB(**user)



async def authenticate_user(email: str, password: str):
    """
    Returns and authenticates the user's instance with given password and email
    """
    user = await get_user(email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    Generates access token and refresh token 
    """
    user = await authenticate_user(form_data["username"], form_data["password"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(config('ACCESS_TOKEN_EXPIRE_MINUTES')))
    refresh_token_expires = timedelta(minutes=int(config('REFRESH_TOKEN_EXPIRE_MINUTES')))
    access_token = create_access_token(
        data={"account": user.email}, expires=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"account": user.email}, expires=refresh_token_expires
    )
    return {"access_token": access_token, "refresh_token": refresh_token}
    

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Checks if the user's logged in or not
    """
    try:
        global payload
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("account")
        if email is None:
            raise HTTPException(detail="Could not validate credentials", status_code=status.HTTP_401_UNAUTHORIZED)
        token_data = TokenPayload(**payload)

        if datetime.fromtimestamp(token_data.exp) < datetime.utcnow():
            raise HTTPException(detail="Token expired", status_code=status.HTTP_401_UNAUTHORIZED)      
        check_res = await check_token_valid(token)
        if check_res != True:
            return check_res
    except JWTError:
        raise HTTPException(detail="Could not validate credentials or token maybe expired", status_code=status.HTTP_403_FORBIDDEN)    
    user = await get_user(email=email)
    if not user:
        raise HTTPException(detail="User not found", status_code=status.HTTP_404_NOT_FOUND)
    
    return user


class PermissionChecker:
    def __init__(self, required_permissions: list[str]) -> None:
        self.required_permissions = required_permissions

    async def __call__(self, base: HTTPAuthorizationCredentials = Depends(security)) -> None | UserDB:
        token = base.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("account")
        user = await get_user(email=email)
        for r_perm in self.required_permissions:
            if r_perm not in user.permissions:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail='Not found!'
                )
        return user