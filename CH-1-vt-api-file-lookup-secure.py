#!/usr/bin/env python2.7
#@JonLittleIT
import requests
import json
import os

url = 'https://www.virustotal.com/vtapi/v2/file/scan'
apikey = os.environ['apikey']

params = {'apikey': apikey}

files = {'file': ('myfile.exe', open('myfile.exe', 'rb'))}

response = requests.post(url, files=files, params=params)

print(response.json())


