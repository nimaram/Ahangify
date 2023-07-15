# from fastapi import FastAPI
# from pydantic import BaseSettings
# from typing import Optional

# core = FastAPI()
      
# # class BookIn(BaseModel):
# #     name: str
# #     description: Optional[str | None] = None
# #     age: Annotated[int | None, Path(title="User's age", ge=0, le=100)] = 18 

# # class BookOut(BaseModel):
# #     name: str
# #     age: int

# # @core.post("/", response_model=BookOut, status_code=status.HTTP_202_ACCEPTED)
# # async def index(inp: BookIn, code: str = Query("No Code!", min_length=6, max_length=8)) -> any:
# #     if inp.name == "Nima":
# #         raise HTTPException(detail="You shouldn't user admin's name!", status_code=status.HTTP_400_BAD_REQUEST, headers={"code": "XEW100"})
# #     return inp