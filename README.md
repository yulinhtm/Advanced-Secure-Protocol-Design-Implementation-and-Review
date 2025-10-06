Advanced-Secure-Protocol-Design-Implementation-and-Review
Group name: Project Groups 20

Group member:

Jiahui Wang a1822691

Yuxuan Wu a1898143

ShunChit Yu a1880719

Youqing Fu a1981355

Mo Yang a1932039

Network protocol: Websocket
Encrytion: RSA
public channel
Json file Style: SOCP(read SOCP V1.3.pdf for more details)

file(all system file is inside the project folder):
The system is vonsist of 3 perts(Introducer, client and server)

Introducer:
IntroducerStorage
Introducer.py
crypto_utils.py

Client:
ClientStorage
TestingClient.py
ClientCommands.py
crypto_utils.py

Server:
ServerStorage
TestingServer.py
crypto_utils.py
server_handlers.py
user.db
bootstrap_servers.yam

Makw sure these file is in the same directory when runnning the system.

Order to start the system:
Introducer -> server -> client

Example command to run the programe:


