# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# server listen port
LISTEN_PORT = 55555

# server max connections
MAX_CONN = 64

# max input length
BUFF = 8096

# logging format
LOGFORMAT = '%(levelname)-10s [%(asctime)s] (%(threadName)-10s) %(message)s'

# force read data timeout
FTIMEOUT = 5.0

# vk api requests timeout
VTIMEOUT = 0.35

# SSL key
SSL_KEY = "server.key"

# SSL cert
SSL_CRT = "server.crt"
