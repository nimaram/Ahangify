from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth

# App object
app = FastAPI()
app.include_router(auth.router, tags=['users'])

origins = ["https://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

