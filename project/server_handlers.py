
"""
ServerHandlers: handle LIST_REQUEST, MSG_DIRECT, MSG_PUBLIC_CHANNEL, FILE_*.
This version injects 'sender' into forwarded public messages and preserves chunk_sig.
"""

import json, time
import hashlib
import crypto_utils as cu

class ServerHandlers:
    def __init__(self, ws_send_func, local_users, user_locations, servers, server_addrs, privkey, server_id):
        self.ws_send = ws_send_func
        self.local_users = local_users        # user_id -> ws
        self.user_locations = user_locations  # user_id -> "local" or server_id
        self.servers = servers                # server_id -> ws
        self.server_addrs = server_addrs
        self.privkey = privkey
        self.server_id = server_id

    def _now_ts(self):
        return int(time.time() * 1000)

    def _sign_payload(self, payload_obj):
        data = cu.canonical_json(payload_obj).encode("utf-8")
        return cu.sign_payload(self.privkey, data)

    async def _send_to_local_user(self, user_id, envelope):
        if user_id in self.local_users:
            await self.ws_send(self.local_users[user_id], json.dumps(envelope))

    async def _send_to_server(self, server_id, envelope):
        if server_id in self.servers:
            await self.ws_send(self.servers[server_id], json.dumps(envelope))

    async def _send_error(self, client_link, to_user, code, detail):
        payload = {"code": code, "detail": detail}
        err = {
            "type": "ERROR",
            "from": self.server_id,
            "to": to_user,
            "ts": self._now_ts(),
            "payload": payload,
            "sig": self._sign_payload(payload)
        }
        await self.ws_send(client_link, json.dumps(err))

    # ---------- /list ----------
    async def handle_list_request(self, envelope, client_link):
        requester = envelope.get("from")
        users = sorted([uid for uid, loc in self.user_locations.items() if loc is not None])
        resp_payload = {"users": users}
        resp = {
            "type": "LIST_RESPONSE",
            "from": self.server_id,
            "to": requester,
            "ts": self._now_ts(),
            "payload": resp_payload,
            "sig": self._sign_payload(resp_payload),
        }
        await self.ws_send(client_link, json.dumps(resp))

    # ---------- /tell ----------
    async def handle_msg_direct(self, envelope, client_link):
        sender    = envelope.get("from")
        recipient = envelope.get("to")
        payload   = envelope.get("payload", {}) or {}

        if recipient not in self.user_locations:
            await self._send_error(client_link, sender, "USER_NOT_FOUND", f"{recipient} not found")
            return

        # 关键：透传原 payload（包含 sig_from/sig_to/sig_ts 等），并补充 sender 字段
        server_payload = dict(payload)
        server_payload.setdefault("sender", sender)

        if self.user_locations[recipient] == "local":
            ud = {
                "type": "USER_DELIVER",
                "from": self.server_id,
                "to": recipient,
                "ts": self._now_ts(),
                "payload": server_payload,
                "sig": self._sign_payload(server_payload),
            }
            await self._send_to_local_user(recipient, ud)
        else:
            sd = {
                "type": "SERVER_DELIVER",
                "from": self.server_id,
                "to": self.user_locations[recipient],
                "ts": self._now_ts(),
                "payload": server_payload,
                "sig": self._sign_payload(server_payload),
            }
            await self._send_to_server(self.user_locations[recipient], sd)



    # ---------- /all (public channel) ----------
    async def handle_msg_public(self, envelope, client_link):
        payload = envelope.get("payload", {})
        sender = envelope.get("from")

        # 精简点：复制 payload，并补充 sender 即可（sender_pub 若在原 payload，就已包含）
        server_payload = dict(payload)
        server_payload.setdefault("sender", sender)

        # dispatch to all users/servers
        for uid, loc in self.user_locations.items():
            if loc == "local":
                ud = {
                    "type": "USER_DELIVER",
                    "from": self.server_id,
                    "to": uid,
                    "ts": self._now_ts(),
                    "payload": server_payload,
                    "sig": self._sign_payload(server_payload),
                }
                await self._send_to_local_user(uid, ud)
            else:
                sd = {
                    "type": "SERVER_DELIVER",
                    "from": self.server_id,
                    "to": loc,
                    "ts": self._now_ts(),
                    "payload": server_payload,
                    "sig": self._sign_payload(server_payload),
                }
                await self._send_to_server(loc, sd)

    # ---------- /file ----------
    async def handle_file_transfer(self, envelope, client_link):
        sender = envelope.get("from")
        recipient = envelope.get("to")
        payload = envelope.get("payload", {})

        if recipient not in self.user_locations:
            await self._send_error(client_link, sender, "USER_NOT_FOUND", f"{recipient} not found")
            return

        # Ensure forwarded payload contains sender; preserve manifest_sig/chunk_sig if present
        fwd_payload = dict(payload)
        fwd_payload.setdefault("sender", sender)

        if self.user_locations[recipient] == "local":
            fd = {
                "type": envelope["type"],
                "from": self.server_id,
                "to": recipient,
                "ts": self._now_ts(),
                "payload": fwd_payload,
                "sig": self._sign_payload(fwd_payload),
            }
            await self._send_to_local_user(recipient, fd)
        else:
            sd = {
                "type": envelope["type"],
                "from": self.server_id,
                "to": self.user_locations[recipient],
                "ts": self._now_ts(),
                "payload": fwd_payload,
                "sig": self._sign_payload(fwd_payload),
            }
            await self._send_to_server(self.user_locations[recipient], sd)
