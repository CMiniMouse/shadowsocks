import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../shadowsocks'))
import common

address = '127.0.0.1'.encode(encoding='utf-8')
address = address.strip(b'.')
print(type(address))
labels = address.split(b'.')
print(labels)

result = []
for label in labels:
    l = len(label)
    result.append(common.chr(l))
    result.append(label)
result.append(b'\0')
print(b''.join(result))


import socket
host = '127.0.0.1'
listen_port = 8388
addrs = socket.getaddrinfo(host, listen_port, 0, socket.SOCK_STREAM, socket.SOL_TCP)

print(addrs)

af, socktype, proto, canonname, sockaddr = addrs[0]
print(sockaddr)
server_socket = socket.socket(af, socktype, proto)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(sockaddr)
server_socket.setblocking(False)
server_socket.listen(1024)
server_socket.close()

import select

if hasattr(select, 'epoll'):
    print('epoll')
if hasattr(select, 'kqueue'):
    print('kqueue')
if hasattr(select, 'select'):
    print('select')

from collections import defaultdict
rlist = ['a', 'b', 'c']
wlist = ['a', 'd', 'e']
result = defaultdict(lambda: 0)
for p in [(rlist, 1), (wlist, 2)]:
    print("p0", p[0])
    for fd in p[0]:
        result[fd] |= p[1]
        print(result)
print(result.items())

def test():
    events = (['a', 'read'], ['b', 'read'], ['c', 'write'])
    return [(1, fd, event) for fd, event in events]
eve = test()
print(eve)
