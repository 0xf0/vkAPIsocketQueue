# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests

login = ""
password = ""
# appid
app_id = 5245132
# scope / права доступа: https://vk.com/dev/permissions
scope = 65536  # offline

session = requests.Session()
response = session.get("https://m.vk.com")
url = re.search(r'action="([^\"]+)"', response.text).group(1)
data = {"email": login, "pass": password}
post = session.post(url, data=data)
data = {
    'response_type': 'token',
    'client_id': app_id,
    'scope': scope,
    'display': 'mobile',
}
response = session.post('https://oauth.vk.com/authorize', data=data)
if 'access_token' not in response.url:
    url = re.search(r'action="([^\"]+)"', response.text).group(1)
    response = session.get(url)
try:
    token = re.search(r'access_token=([^&]+)', response.url).group(1)
    print(token)
except Exception as e:
    print("Whoops: {}".format(e))
