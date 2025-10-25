"""
Group 20:
Jiahui Wang a1822691
Yuxuan Wu a1898143
ShunChit Yu a1880719
Youqing Fu a1981355
Mo Yang a1932039
"""

import json, time
import hashlib
import crypto_utils as cu
import websockets

class ServerHandlers:
    def __init__(self, ws_send_func, local_users, user_locations, servers, server_addrs, privkey, server_id, resolve_username=None):
        self.ws_send = ws_send_func
        self.local_users = local_users        # user_id -> ws

        self.user_locations = user_locations  # user_id -> "local" or server_id

        self.servers = servers                # server_id -> ws

        self.server_addrs = server_addrs
        self.privkey = privkey
        self.server_id = server_id
        self.resolve_username = resolve_username

    def _now_ts(self):
        return int(time.time() * 1000)

    def _sign_payload(self, payload_obj):
        data = cu.canonical_json(payload_obj).encode("utf-8")
        return cu.sign_payload(self.privkey, data)

    async def _send_to_local_user(self, user_id, envelope):
        if user_id in self.local_users:
            await self.ws_send(self.local_users[user_id], json.dumps(envelope))

    async def _send_to_server(self, server_id, envelope, server_addrs):
        if server_id in self.servers:
            info = server_addrs.get(server_id)
            host = info.get("host")
            port = info.get("port")
            uri = f"ws://{host}:{port}"
            async with websockets.connect(uri) as ws:
                await ws.send(json.dumps(envelope))

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

    # ----------/list ----------

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

    # ----------/tell ----------

    async def handle_msg_direct(self, envelope, client_link, server_addrs):
        sender_id    = envelope.get("from")
        recipient = envelope.get("to")
        payload   = envelope.get("payload", {}) or {}

        if recipient not in self.user_locations:
            await self._send_error(client_link, sender_id, "USER_NOT_FOUND", f"{recipient} not found")
            return

        # Key: Transparently transmit the original payload (including sig_from/sig_to/sig_ts, etc.), and add the sender field

        server_payload = dict(payload)
        display_name = self.resolve_username(sender_id) if self.resolve_username else sender_id
        server_payload["sender"] = display_name
        # print("[DEBUG server_payload]\n" + json.dumps(server_payload, indent=2))


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
            print("sending to other server")
            await self._send_to_server(self.user_locations[recipient], sd, server_addrs)



    # ----------/all (public channel) ----------

    async def handle_msg_public(self, envelope, client_link, server_addrs):
        sender  = envelope.get("from")
        ts      = envelope.get("ts")
        payload = envelope.get("payload", {}) or {}

        try:
            import hashlib
            sender_pub = cu.deserialize_publickey(payload["sender_pub"])
            text = payload.get("text", "")
            dg   = hashlib.sha256((text + sender + str(ts)).encode("utf-8")).digest()
            if not cu.verify_signature(sender_pub, dg, payload.get("content_sig", "")):
                await self._send_error(client_link, sender, "INVALID_SIG", "bad content_sig")
                return
        except Exception:
            await self._send_error(client_link, sender, "INVALID_SIG", "bad content_sig")
            return

        display = self.resolve_username(sender) if self.resolve_username else sender
        base_payload = dict(payload)
        base_payload["sender"] = display

        for uid, loc in self.user_locations.items():
            if loc == "local":
                env = {
                    "type": "MSG_PUBLIC_CHANNEL",
                    "from": self.server_id,
                    "to":   uid,
                    "ts":   self._now_ts(),
                    "payload": base_payload,
                }
                env["sig"] = self._sign_payload(base_payload) 
                await self._send_to_local_user(uid, env)
            else:
                per_user_payload = dict(base_payload)
                per_user_payload["user_id"] = uid
                per_user_payload["mtype"]   = "MSG_PUBLIC_CHANNEL"

                sd = {
                    "type": "SERVER_DELIVER",
                    "from": self.server_id,
                    "to":   loc,  # server_id for routing

                    "ts":   self._now_ts(),
                    "payload": per_user_payload,
                }
                sd["sig"] = self._sign_payload(per_user_payload)
                await self._send_to_server(loc, sd, server_addrs)


    # ----------/file ----------

    async def handle_file_transfer(self, envelope, client_link, server_addrs):
        sender = envelope.get("from")
        recipient = envelope.get("to")
        payload = envelope.get("payload", {})

        if recipient not in self.user_locations:
            await self._send_error(client_link, sender, "USER_NOT_FOUND", f"{recipient} not found")
            return

        # Add sender when forwarding (retain manifest_sig /chunk_sig)

        display = self.resolve_username(sender) if self.resolve_username else sender
        fwd_payload = dict(payload)
        fwd_payload["sender"] = display

        if self.user_locations[recipient] == "local":
            fd = {
                "type": envelope["type"],
                "from": self.server_id,
                "to": recipient,                      # local user

                "ts": self._now_ts(),
                "payload": fwd_payload,
                "sig": self._sign_payload(fwd_payload),
            }
            await self._send_to_local_user(recipient, fd)
        else:
            sd = {
                "type": envelope["type"],
                "from": self.server_id,
                "to": recipient,                      # ★ Key: Also use the "target user ID" when crossing servers!

                "ts": self._now_ts(),
                "payload": fwd_payload,
                "sig": self._sign_payload(fwd_payload),
            }
            # Send a long connection through the established peer server (use server_id to select the route, but envelope.to is still the user ID)

            await self._send_to_server(self.user_locations[recipient], sd, server_addrs)

