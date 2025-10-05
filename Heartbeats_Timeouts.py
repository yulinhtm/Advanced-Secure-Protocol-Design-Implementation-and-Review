# Heartbeats_Timeouts.py
import asyncio
import time
import json
import websockets
from typing import Dict, Tuple, Optional

# --- Module Variables (injected from main/testing server) ---
# these will be set by the main server process like:
# hb.servers = servers
# hb.server_addrs = server_addrs
# hb.last_seen_times = last_seen_times
# hb.SERVER_ID = SERVER_ID
# hb.private_key = private_key
# hb.sign_payload = sign_payload

servers: Dict[str, websockets.WebSocketClientProtocol] = {}
server_addrs: Dict[str, Tuple[str, int]] = {}   # server_id -> (host, port)
last_seen_times: Dict[str, int] = {}            # server_id -> timestamp ms
SERVER_ID: str = ""
private_key = None           # optional, may be set by main if you want real signatures
sign_payload = None          # optional function: sign_payload(privkey, bytes) -> str

HEARTBEAT_INTERVAL = 15      # seconds
MONITOR_INTERVAL = 10        # seconds
TIMEOUT_MS = 45_000          # 45 seconds in ms
RECONNECT_BACKOFF = 5        # base seconds (exponential backoff applied)


async def send_heartbeats_periodically():
    """Periodically send HEARTBEAT to each connected server in `servers`."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        peer_count = len(servers)
        print(f"[{time.ctime()}] Sending heartbeats to {peer_count} servers...")
        for server_id, ws in list(servers.items()):
            try:
                heartbeat_msg = {
                    "type": "HEARTBEAT",
                    "from": SERVER_ID,
                    "to": server_id,
                    "ts": int(time.time() * 1000),
                    "payload": {},
                    # default placeholder sig (so sig key always present)
                    "sig": "..."
                }

                # 看看是否可行，不可行直接删除关于sig的功能
                # if real signing is available, produce a signature and replace placeholder
                if sign_payload and private_key:
                    try:
                        # canonicalize payload bytes and sign; sign_payload(privkey, bytes) expected
                        payload_bytes = json.dumps(heartbeat_msg["payload"], sort_keys=True, separators=(',', ':')).encode("utf-8")
                        heartbeat_msg["sig"] = sign_payload(private_key, payload_bytes)
                    except Exception as e:
                        print(f"[HB SIGN ERROR] failed to sign heartbeat for {server_id}: {e}")

                # debug print of message
                print(f"[HB -> {server_id}] {json.dumps(heartbeat_msg)}")

                # send (if ws open)
                if ws and getattr(ws, "open", True):
                    await ws.send(json.dumps(heartbeat_msg))
                else:
                    print(f"[HB SEND] socket for {server_id} not open; removing")
                    servers.pop(server_id, None)
                    last_seen_times.pop(server_id, None)
            except websockets.ConnectionClosed:
                print(f"[HB SEND] ConnectionClosed when sending to {server_id}")
                servers.pop(server_id, None)
                last_seen_times.pop(server_id, None)
            except Exception as e:
                print(f"[HB SEND] Error sending heartbeat to {server_id}: {e}")


async def monitor_connections_periodically():
    """Check last_seen_times and close/reconnect timed-out peers."""
    backoffs: Dict[str, int] = {}  # server_id -> backoff seconds
    while True:
        await asyncio.sleep(MONITOR_INTERVAL)
        now_ms = int(time.time() * 1000)
        # debug print
        # print(f"[MONITOR] now={now_ms}, last_seen={last_seen_times}")
        for server_id in list(set(list(servers.keys()) + list(last_seen_times.keys()))):
            last_seen = last_seen_times.get(server_id)
            if not last_seen:
                # no record yet; skip for now
                continue
            elapsed = now_ms - last_seen
            if elapsed > TIMEOUT_MS:
                print(f"[MONITOR] Connection to server {server_id} timed out (last seen {elapsed} ms). Cleaning up and attempting reconnect.")
                ws = servers.pop(server_id, None)
                last_seen_times.pop(server_id, None)
                try:
                    if ws and getattr(ws, "open", False):
                        await ws.close()
                except Exception:
                    pass

                addr = server_addrs.get(server_id)
                # schedule reconnect with exponential backoff
                if addr:
                    backoff = backoffs.get(server_id, RECONNECT_BACKOFF)
                    print(f"[MONITOR] scheduling reconnect to {server_id} in {backoff}s")
                    asyncio.create_task(_reconnect_with_backoff(server_id, addr, backoff, backoffs))
            else:
                # alive - optionally print small debug
                # print(f"[MONITOR] {server_id} alive, {elapsed} ms since last_seen")
                pass


async def _reconnect_with_backoff(server_id: str, addr: Tuple[str, int], backoff: int, backoffs: Dict[str,int]):
    await asyncio.sleep(backoff)
    try:
        await reconnect_to_server(server_id, addr)
        # success -> reset backoff
        if server_id in backoffs:
            backoffs.pop(server_id, None)
    except Exception as e:
        # increase backoff and reschedule
        nxt = min(backoff * 2, 300)  # cap at 5 minutes
        backoffs[server_id] = nxt
        print(f"[RECONNECT] failed to connect to {server_id}: {e} -> next backoff {nxt}s")
        asyncio.create_task(_reconnect_with_backoff(server_id, addr, nxt, backoffs))


async def reconnect_to_server(server_id: str, addr: Tuple[str, int]):
    """Try to connect to server and store ws in servers[] and update last_seen_times."""
    host, port = addr
    uri = f"ws://{host}:{port}"
    print(f"[RECONNECT] Trying to connect to {server_id} at {uri}")
    try:
        ws = await websockets.connect(uri)
        servers[server_id] = ws
        last_seen_times[server_id] = int(time.time() * 1000)
        print(f"[RECONNECT] Connected to {server_id} ({uri})")
        # optional: start a small reader task to keep last_seen updated for this client-side socket
        asyncio.create_task(_read_peer_loop(server_id, ws))
    except Exception as e:
        print(f"[RECONNECT] Failed to connect to {server_id} at {uri}: {e}")
        raise


async def _read_peer_loop(server_id: str, ws):
    """When we actively connect (client side), optionally read frames to keep last_seen updated."""
    try:
        async for raw in ws:
            # try parse messages
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            # update last_seen when we receive anything from peer
            last_seen_times[server_id] = int(time.time() * 1000)
            # optionally log heartbeat receipts
            if msg.get("type") == "HEARTBEAT":
                print(f"[HB <- {server_id}] Received heartbeat: {msg}")
    except websockets.ConnectionClosed:
        print(f"[READER] connection closed for {server_id}")
        servers.pop(server_id, None)
        last_seen_times.pop(server_id, None)
    except Exception as e:
        print(f"[READER] error reading from {server_id}: {e}")
        servers.pop(server_id, None)
        last_seen_times.pop(server_id, None)

# helper to allow other modules to update last_seen when receiving messages
def mark_peer_seen(server_id: str):
    if server_id:
        last_seen_times[server_id] = int(time.time() * 1000)
