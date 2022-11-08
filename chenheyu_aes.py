from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
# from java.util import Base64
# import base64
# import hashlib
# import json
# from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import padding
import re

from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import SecretKeySpec

from java.util import Base64
class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("chenheyu_AES")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return U2CTab(self, controller, False)
        
# 
# class implementing IMessageEditorTab
#

class U2CTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our u2c data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "chenheyu_AES"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # Check response if containing unicode character
        contentStr = self._extender._helpers.bytesToString(content)
        # regexp = re.compile(r'\\u[a-z0-9]{4}')
        # existsUnicode = regexp.search(contentStr.lower())
        return (not isRequest) and contentStr

    # def decrypt(payload):
    #     return runExternal("crypto.py", "decrypt", payload.tostring())


    # def setMessage(self, content, isRequest):
    #     if content is None:
    #         # clear our display
    #         self._txtInput.setText(None)
    #         self._txtInput.setEditable(False)
    #
    #     else:
    #         # Convert Unicode to Chines()e
    #         contentStr = self._extender._helpers.bytesToString(content)
    #         secret_key = 'groupappEncrypk1'
    #         # data = "OUF2M0iEwcDO77zB+uUxf5oMVlbsm6Der+qucpEvKAIAZyUsYDkZ5YRXzxRVo8srA8UC8L23Ass0dcpUpJebfI+0WSzh5gxCuMO5If6UBb0="
    #         block_size = 128
    #         secret_key = secret_key.encode("utf-8")
    #         data = base64.b64decode(contentStr)
    #
    #         cipher = Cipher(
    #             algorithms.AES(secret_key),
    #             mode=modes.ECB(),
    #             backend=default_backend()
    #         )
    #         decryptor = cipher.decryptor()
    #         decrypt_data = decryptor.update(data)
    #         unpadder = padding.PKCS7(block_size).unpadder()
    #         unpad_decrypt_data = unpadder.update(decrypt_data) + unpadder.finalize()
    #         # self._txtInput.setText(
    #         #     self._extender._helpers.stringToBytes(
    #         #         contentStr.decode('unicode-escape').encode('utf-8')
    #         #     )
    #         # )
    #         self._txtInput.setText(
    #             unpad_decrypt_data.decode("utf-8")
    #         )
    #         self._txtInput.setEditable(self._editable)
    #
    #     # remember the displayed content
    #     self._currentMessage = content
    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        else:
            # Convert Unicode to Chines()e
            contentStr = self._extender._helpers.bytesToString(content)
            key = 'groupappEncrypk1'
            decoded = Base64.getDecoder().decode(content)
            aesKey = SecretKeySpec(key, "AES")
            # aesIV = IvParameterSpec(iv)
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, aesKey)
            # self._txtInput.setText(
            #     self._extender._helpers.stringToBytes(
            #         contentStr.decode('unicode-escape').encode('utf-8')
            #     )
            # )
            self._txtInput.setText(
               cipher.doFinal(decoded)
            )
            self._txtInput.setEditable(self._editable)

        # remember the displayed content
        self._currentMessage = content

    def getMessage(self):
        # don't change the original response
        return self._currentMessage
    
    def isModified(self):
        return False
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()

