# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import json
from lib import cons
from lib import aes

token = ""  # paste your token
userid = "210700286"  # paste your user id
data = {"method": "users.get", "token": token, "params": {"user_ids": userid}}
cipher = aes.AESModeOfOperation()
mode, orig_len, ciph = cipher.encrypt(json.dumps(data), cipher.modeOfOperation["OFB"], cons.CKEY,
                                      cipher.aes.keySize["SIZE_256"], cons.IV)

for i in range(25):
    sock = socket.socket()
    sock.connect(("localhost", cons.LISTEN_PORT))
    sock.send(" ".join(str(x) for x in ciph).encode())

    data = sock.recv(1024)
    sock.close()

    sdata = data.decode("utf-8").split(" ")
    ldata = ([int(x) for x in sdata])
    decr = cipher.decrypt(ldata, False, cipher.modeOfOperation["OFB"], cons.CKEY,
                          cipher.aes.keySize["SIZE_256"], cons.IV)
    # j = json.loads(decr)
    # print(j["response"])
    print(decr)
