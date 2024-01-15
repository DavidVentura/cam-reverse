import socket
import time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = "192.168.1.255"
ip = "192.168.1.1"
send_port = 32108
recv_port = 49512
s.bind(("", recv_port))
#s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

DISCOVER_PKT = bytes([0xf1, 0x30, 0x00, 0x00])
def send(data):
    s.sendto(data, (ip, send_port))

send(DISCOVER_PKT)
data, server = s.recvfrom(4095)
print(data, server)
time.sleep(0.1)

"""
b'\xf1A\x00\x14BATC\x00\x00\x00\x00\x00\tM,HVDCS\x00\x00\x00'

0000   14 ac 60 29 81 bf 84 36 71 17 be 90 08 00 45 00   ..`)...6q.....E.
0010   00 34 00 2f 00 00 ff 11 37 d4 c0 a8 01 01 c0 a8   .4./....7.......
0020   01 64 7d 6c c1 68 00 20 88 79 f1 41 00 14 42 41   .d}l.h. .y.A..BA
0030   54 43 00 00 00 00 00 09 4d 2c 48 56 44 43 53 00   TC......M,HVDCS.
0040   00 00                                             ..
"""

send(bytes([0xf1, 0xe1, 0x00, 0x00]))
data, server = s.recvfrom(4095)
print(data, server)
time.sleep(0.1)
