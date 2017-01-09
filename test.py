# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import json
import socket
from core import cons

token = ""  # paste your token
userid = "210700286"  # paste your user id
data = {"method": "users.get", "token": token, "params": {"user_ids": userid}}

for i in range(1):
    sock = socket.socket()
    ssl_wrap = ssl.wrap_socket(sock, ca_certs=cons.SSL_CRT, cert_reqs=ssl.CERT_REQUIRED)
    ssl_wrap.connect(("localhost", cons.LISTEN_PORT))
    ssl_wrap.send(json.dumps(data).encode())

    data = ssl_wrap.recv(1024).decode("utf-8")
    ssl_wrap.close()
    print(data)
