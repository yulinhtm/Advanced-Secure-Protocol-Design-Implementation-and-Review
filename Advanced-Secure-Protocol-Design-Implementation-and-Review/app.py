from fastapi import FastAPI, Form
import uvicorn
import asyncio
import websockets
from TestingClient import load_server_pubkey
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
    # 1) 先读取服务器公钥（用于注册时加密/验签）
    server_pubkey = load_server_pubkey()
    if server_pubkey is None:
        return {"success": False, "error": "server_public_key.pem not found or invalid"}

    # 2) 连接后端 WebSocket，再把公钥一并传给 TestingClient.register
    async with websockets.connect("ws://localhost:8765") as ws:
        success = await TestingClient.register(ws, username, password, server_pubkey)

    return {"success": success}

@app.post("/login")
async def login_user(username: str = Form(...), password: str = Form(...)):
    async with websockets.connect("ws://localhost:8765") as ws:
        success = await TestingClient.login(ws, username, password)
        return {"success": success}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
