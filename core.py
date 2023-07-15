from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import song

# App object
app = FastAPI()
app.include_router(song.router, tags=['song'])

origins = ["https://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

