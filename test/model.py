from pydantic import BaseModel


class Patch(BaseModel):
    op: str
    path: str
    value: str
s