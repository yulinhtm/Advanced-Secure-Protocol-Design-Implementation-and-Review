import json
import asyncio
import websockets
import traceback

local_users = {}
user_locations = {}
SERVER_ID = "server-1"

async def handle_connection(ws):
    print("ws is:", ws)
    try:
        async for message in ws:
            try:
                msg = json.loads(message)
            except json.JSONDecodeError:
                await ws.send(json.dumps({"type": "ERROR", "payload": {"code": "INVALID_JSON"}}))
                continue

            print("Received:", msg)
            msg_type = msg.get("type")

            if msg_type == "USER_HELLO":
                user_id = msg.get("from")
                payload = msg.get("payload", {})
                pubkey = payload.get("pubkey")

                if not user_id or not pubkey:
                    await ws.send(json.dumps({"type": "ERROR", "payload": {"code": "INVALID_MESSAGE"}}))
                    continue

                # check duplicate
                if user_id in local_users:
                    await ws.send(json.dumps({"type": "ERROR", "payload": {"code": "NAME_IN_USE"}}))
                    continue

                # store in memory
                local_users[user_id] = ws
                user_locations[user_id] = "local"

                # ACK
                ack = {"type": "ACK", "from": SERVER_ID, "to": user_id,
                       "payload": {"msg_ref": "USER_HELLO"}}
                await ws.send(json.dumps(ack))
                print(f"User {user_id} registered successfully!")

    except websockets.ConnectionClosed:
        print("Client disconnected")
    except Exception as e:
        print("Server error:")
        traceback.print_exc()


async def main():
    async with websockets.serve(handle_connection, "localhost", 8765):
        print("Server running on ws://localhost:8765")
        await asyncio.Future()  # run forever

asyncio.run(main())

