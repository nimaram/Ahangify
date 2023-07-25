from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth, core
from decouple import config


# App object
app = FastAPI()
app.include_router(auth.router, tags=["users"])
app.include_router(core.router, tags=["general"])
origins = [f"{config('BASE_SITE')}"]



app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

