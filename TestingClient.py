import asyncio
import websockets
import json

async def main():
    try:
        async with websockets.connect("ws://localhost:8765") as ws:
            msg = {
                "type": "USER_HELLO",
                "from": "alice",
                "to": "server-1",
                "payload": {"pubkey": "FAKEPUBKEY"}
            }
            await ws.send(json.dumps(msg))

            # wait for server response
            response = await ws.recv()
            print("Server response:", response)

    except websockets.ConnectionClosed as e:
        print(f"Connection closed: {e.code} - {e.reason}")
    except Exception as e:
        print("Client error:", e)

asyncio.run(main())


