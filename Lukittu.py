from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import base64
import winreg
import os

class Lukittu:
    def __init__(self, teamId: str, productId: str, pubKeyBase64: str):
        self.teamId = teamId
        self.productId = productId
        self.pubKey = base64.b64decode(pubKeyBase64)

    def _verifyResponse(self) -> bool:
        publicKey = serialization.load_pem_public_key(self.pubKey)
        signature = bytes.fromhex(self.challengeResponse)

        try:
            publicKey.verify(
                signature,
                self.challenge.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return True

        except Exception:
            return False
    
    def _getHwid(self) -> (bool, str):
        try:
            registryPath = r"SOFTWARE\Microsoft\Cryptography"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registryPath)
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)

            return True, value

        except Exception as e:
            return False, e

    def _sendRequest(self) -> (bool, str):
        url = f"https://app.lukittu.com/api/v1/client/teams/{self.teamId}/verification/verify"

        status, response = self._getHwid()
        if not status:
            return False, response

        self.challenge = os.urandom(32).hex()
        payload = {
            "licenseKey": self.licenseKey,
            "challenge": self.challenge,
            "hardwareIdentifier": response,
            "productId": self.productId
        }

        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()

        if data["result"]["code"] == "VALID":
            self.challengeResponse = data["result"]["challengeResponse"]
            return True, data["result"]["details"]

        return False, data["result"]["details"]

    def verifyLicense(self, licenseKey: str) -> bool:
        self.licenseKey = licenseKey

        status, response = self._sendRequest()
        if status and self._verifyResponse():
            return True
        else:
            print(response)
            return False