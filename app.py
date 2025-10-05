from fastapi import FastAPI, Form
import uvicorn
import asyncio
import websockets
import TestingClient  # your file with register/login functions

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index1.html", {"request": request})


@app.post("/register")
async def register_user(username: str = Form(...), password: str = Form(...)):
    async with websockets.connect("ws://localhost:8765") as ws:
        success = await TestingClient.register(ws, username, password)
        return {"success": success}

@app.post("/login")
async def login_user(username: str = Form(...), password: str = Form(...)):
    async with websockets.connect("ws://localhost:8765") as ws:
        success = await TestingClient.login(ws, username, password)
        return {"success": success}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
