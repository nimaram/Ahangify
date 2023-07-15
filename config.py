from motor.motor_asyncio import AsyncIOMotorClient
from decouple import config

MONGODB_URL = config('MONGODB_URL')

client = AsyncIOMotorClient(MONGODB_URL)

# database config
database = client.Ahang
collection = database.Song

async def create_song(song):
    document = song
    result = await collection.insert_one(document)
    return result