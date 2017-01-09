# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import socket
import ssl
from pprint import pprint

from core import cons


def recvall(_s, buffer_size=8096):
    buf = _s.recv(buffer_size)
    while buf:
        yield buf
        buf = _s.recv(buffer_size)

token = ""  # paste your token
userid = "210700286"  # paste your user id
data = {"method": "users.get", "token": token, "params": {"user_ids": userid}}

for i in range(10):
    sock = socket.socket()
    ssl_wrap = ssl.wrap_socket(sock, ca_certs=cons.SSL_CRT, cert_reqs=ssl.CERT_REQUIRED)
    ssl_wrap.connect(("localhost", cons.LISTEN_PORT))
    ssl_wrap.sendall(json.dumps(data).encode())
    response = b"".join(recvall(ssl_wrap))
    ssl_wrap.close()
    sock.close()
    pprint(json.loads(response.decode("utf-8")))
