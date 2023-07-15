from motor.motor_asyncio import AsyncIOMotorClient
import os


MONGODB_URL = os.environ["MONGODB_URL"]

client = AsyncIOMotorClient(MONGODB_URL)

# database config
database = client.python_db