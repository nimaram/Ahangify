from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth, core
from decouple import config
from contextlib import asynccontextmanager
from fastapi_utils.tasks import repeat_every
from database import UsersCollection, reset_password_tokens, VerificationCode, token_blacklist
from datetime import datetime, timedelta
from fastapi.staticfiles import StaticFiles



@repeat_every(seconds=300)
async def check_and_delete_invalid_data() -> None:
        """
        Usage: Finds disabled accounts every 5 minutes and delete those 
        to release memory for better performance (accounts and tokens that lasted for 10 minutes)
        Also, this function delete expired reset tokens
        """
        try:
            await UsersCollection.delete_many({"user_type": "disabled", "created_at": {"$lte": datetime.utcnow() - timedelta(minutes=10)}})
            await VerificationCode.delete_many({"created_at": {"$lte": datetime.utcnow() - timedelta(minutes=10)}})
            await reset_password_tokens.delete_many({"expired_at": {"$lte": datetime.utcnow()}})
            await token_blacklist.delete_many({"exp": {"$lte": datetime.utcnow()}})
        except:
            raise ValueError("Can't connect to the database, or wrong data(0xEDC200)")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    App lifespan
    Manage what happens during startup or shutdown
    """
    # codes that trigger before startup
    await check_and_delete_invalid_data()
    yield
    # codes that trigger before shutdown



# App object
app = FastAPI(lifespan=lifespan)
app.include_router(auth.router, tags=["users"])
app.include_router(core.router, tags=["artist_panel"])



app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

