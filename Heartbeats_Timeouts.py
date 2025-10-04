import asyncio
import time
import json
import websockets
from crypto_utils import *


# --- Module Variables (will be injected from main) ---
servers = {}           # server_id -> ws
server_addrs = {}      # server_id -> (host, port)
last_seen_times = {}   # server_id -> last heartbeat timestamp(ms)
SERVER_ID = ""
private_key = None
sign_payload = None 


local_users = {}      # user_id  -> ws
user_locations = {}   # user_id  -> "local" | server_id


# --- NEW: Heartbeat and Monitoring Functions ---

async def send_heartbeats_periodically():
    """Periodically sends HEARTBEAT messages to all connected servers."""
    while True:
        await asyncio.sleep(15)  # Send every 15 seconds
        print(f"[{time.ctime()}] Sending heartbeats to {len(servers)} servers...")

        for server_id, ws in list(servers.items()):
            try:
                heartbeat_msg = {
                    "type": "HEARTBEAT",
                    "from": SERVER_ID,
                    "to": server_id,
                    "ts": int(time.time() * 1000),
                    "payload": {},
                    "sig":" "
                }   
                await ws.send(json.dumps(heartbeat_msg))
            except websockets.ConnectionClosed:
                print(f"Failed to send heartbeat to {server_id}, connection is already closed.")
            except Exception as e:
                print(f"Error sending heartbeat to {server_id}: {e}")


async def monitor_connections_periodically():
    """Monitors server connections and handles timeouts."""
    while True:
        await asyncio.sleep(10)  # Check every 10 seconds
        current_time_ms = int(time.time() * 1000)

        for server_id in list(servers.keys()):
            last_seen = last_seen_times.get(server_id)
            if last_seen and (current_time_ms - last_seen) > 45000:  # 45-second timeout
                print(f"Connection to server {server_id} timed out. Closing connection.")

                ws = servers.pop(server_id, None)
                last_seen_times.pop(server_id, None)

                if ws and ws.open:
                    await ws.close()

                # Try reconnect
                addr = server_addrs.get(server_id)
                if addr:
                    asyncio.create_task(reconnect_to_server(server_id, addr))


async def reconnect_to_server(server_id, addr):
    """Try to (re)connect to another server and store the websocket."""
    host, port = addr
    try:
        print(f"Trying to connect to {server_id} at ws://{host}:{port}")
        ws = await websockets.connect(f"ws://{host}:{port}")
        servers[server_id] = ws
        last_seen_times[server_id] = int(time.time() * 1000)
        print(f"Connected to {server_id}")
    except Exception as e:
        print(f"Failed to connect to {server_id}: {e}")

