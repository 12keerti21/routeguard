from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import items, admin

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
app.include_router(items.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
