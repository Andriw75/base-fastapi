from pydantic import BaseModel

class UserResponse(BaseModel):
    name:str
    permissions:list[str] = []
    
class UserDb(UserResponse):
    id:int
    password:str