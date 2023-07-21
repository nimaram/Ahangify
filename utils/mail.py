from fastapi_mail import FastMail, ConnectionConfig
from pydantic import EmailStr, BaseModel
from decouple import config


class EmailSchema(BaseModel):
    email: list[EmailStr]


config = ConnectionConfig(
    MAIL_USERNAME = config("MAIL_USERNAME"),
    MAIL_PASSWORD = config("MAIL_PASSWORD"),
    MAIL_FROM = config("MAIL_FROM"),
    MAIL_PORT = config("MAIL_PORT"),
    MAIL_SERVER = config("MAIL_SERVER"),
    MAIL_FROM_NAME=config("MAIL_FROM_NAME"),
    MAIL_STARTTLS = config("MAIL_STARTTLS"),
    MAIL_SSL_TLS = config("MAIL_SSL_TLS"),
    USE_CREDENTIALS = config("USE_CREDENTIALS"),
    VALIDATE_CERTS = config("VALIDATE_CERTS")
)

mail_service = FastMail(config)