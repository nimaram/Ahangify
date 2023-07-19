from datetime import datetime, timedelta
import jwt
from decouple import config

JWT_SECRET = config("SECRET_KEY")
JWT_ALGORITHM = config("JWT_ALGORITHM")

def create_access_token():
    pass
    