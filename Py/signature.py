# draft 

import requests
import base64
import datetime
import ecdsa
import hashlib
import json

t0 = datetime.datetime(1, 1, 1)
now = datetime.datetime.utcnow()
seconds = (now - t0).total_seconds()+3*60*60
ticks = seconds * 10**7
nonce = str(int(ticks))


privateKey = "MIHc****"
id = "<Guid>"


body = dict()
body['FromDate'] = (datetime.datetime.now()+datetime.timedelta(days=-400, hours=-5)).isoformat()+'1+03:00'
body['ToDate'] = (datetime.datetime.now()+datetime.timedelta(days=-400, hours=0)).isoformat()+'+03:00'
body['SourceCurrencies'] = [74]
body['TargetCurrencies'] = [173]

signatureRawData = f"{json.dumps(body)}{nonce}".lower().replace(' ','')
signatureRawDataBytes = signatureRawData.encode('utf-8')
signatureRawDataHash = hashlib.sha512(signatureRawDataBytes)
secretKeyByteArray = base64.b64decode(privateKey)
#secretKeyByteArray.decode('ascii')


sk = ecdsa.SigningKey.from_der(secretKeyByteArray)
signatureBytes = sk.sign_digest(signatureRawDataHash.digest())
signatureHex = signatureBytes.hex()

signature = f"{signatureHex}:{id}:{nonce}".upper()


BaseUri = "https://api.netex24.net/api/Merchants/GetBalance"

headers = {'Content-Type': 'application/json',
           'ECDSA': signature}
ans0 = requests.post(BaseUri, headers=headers, data=json.dumps(body).replace(' ', ''))
qq = ans0.json()
print(qq)