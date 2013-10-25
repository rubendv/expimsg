import socket
import 

server_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
server_s.bind(("127.0.0.1", 45678))
client_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
client_s.bind(("127.0.0.1", 45679))
client_s.sendto("Hello, world!", ("127.0.0.1", 45678))
print server_s.recvfrom(1000)

