from Crypto.Cipher import AES
from Crypto import Random
from Tkinter import Tk, TclError
import socket
import base64
import atexit
from select import select
import os.path

class pyClipboardShare:
    rootTK=None
    KEY_FILE = 'key.aes'
    KEY = ''
    crypt=None
    PORT=34236
    SOCK_OUT=None
    SOCK_IN=None
    currentText=''
    pause=False
    buffers={}
    DEBUG=False
    running=True
    ownIP=None
    packetMax=1024*1024
    
    def __init__(self):
        self.rootTK = Tk()
        self.rootTK.withdraw()

        self.getOwnIP()
        if (self.DEBUG): print('IP: ' + self.ownIP)

        self.getKey()
        self.crypt = AES.new(self.KEY, AES.MODE_ECB)

        if (self.DEBUG): print('Setting up broadcast socket ...')
        self.SOCK_OUT = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.SOCK_OUT.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if (self.DEBUG): print('Setting up listening socket ...')
        self.SOCK_IN = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.SOCK_IN.bind(('', self.PORT))

        self.currentText = self.getClipboard()

        self.rootTK.after(100, self.watchClipboard)
        self.rootTK.after(100, self.watchBroadcast)

        atexit.register(self.stop)

        self.rootTK.protocol("WM_DELETE_WINDOW", self.stop)
        self.rootTK.mainloop()

    def stop(self):
        self.SOCK_OUT.close()
        self.SOCK_IN.close()
        self.running = False
        self.rootTK.destroy()

    def getOwnIP(self):
        IPs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        IPs.connect(('8.8.8.8', 53))
        self.ownIP = IPs.getsockname()[0]
        IPs.close()

    def watchClipboard(self):
        if not(self.pause):
            text = self.getClipboard()
            if text != None and text != self.currentText:
                if (self.DEBUG): print('Clipboard changed: ' + text)
                self.currentText = text
                self.send(self.encrypt(text))
        self.rootTK.after(100, self.watchClipboard)

    def watchBroadcast(self):
        lr, lw, lx = select([self.SOCK_IN], [], [], 0)
        if lr:
            data = self.SOCK_IN.recvfrom(self.packetMax)
            
            if data[1][0] != self.ownIP:
                if not(data[1] in self.buffers):
                    self.buffers[data[1]] = ''
                self.buffers[data[1]] += data[0]
                if (self.DEBUG): print('Recieved data from ' + data[1][0] + ': ' + data[0])

                self.pause = True
                while '\00' in self.buffers[data[1]]:
                    chunk, rest = self.buffers[data[1]].split('\00', 1)
                    self.buffers[data[1]] = rest
                    
                    if (self.DEBUG): print('Recieved chunk: ' + chunk)
                    decoded = base64.decodestring(chunk)
                    if (self.DEBUG): print('Decoded chunk: ' + decoded)
                    self.currentText = self.decrypt(decoded)
                    self.setClipboard(self.currentText)
                self.pause = False
        self.rootTK.after(100, self.watchBroadcast)
        
    def encrypt(self, text):
        text += '\00'
        short = 16 - (len(text) % 16)
        text += Random.get_random_bytes(short)
        data = self.crypt.encrypt(text)
        if (self.DEBUG): print('Encrypted data: ' + data)
        return data

    def decrypt(self, data):
        text = self.crypt.decrypt(data)
        return text.split('\00')[0]
    
    def send(self, data):
        outData = base64.encodestring(data) + '\00'
        while outData:
            chunk = outData[:self.packetMax]
            outData = outData[self.packetMax:]
            self.SOCK_OUT.sendto(chunk, ('255.255.255.255', self.PORT))
            if (self.DEBUG): print('Sent data: ' + chunk)

    def getClipboard(self):
        text = None
        try:
            text = self.rootTK.clipboard_get()
        except TclError:
            pass
        return text

    def setClipboard(self, text):
        self.rootTK.clipboard_clear()
        self.rootTK.clipboard_append(text)
        if (self.DEBUG): print('Set clipboard text: ' + text)

    def makeKey(self):
        self.KEY = raw_input('Enter key or leave blank to generate: ')
        if not(self.KEY):
            self.KEY = Random.get_random_bytes(32)

        KEY_LEN = len(self.KEY)

        if KEY_LEN != 16 and KEY_LEN != 24 and KEY_LEN != 32:
            if KEY_LEN < 16:
                print('Key must be atleast 16 characters long')
                self.makeKey()
                return
            elif KEY_LEN < 24:
                self.KEY = self.KEY[:16]
            elif KEY_LEN < 32:
                self.KEY = self.KEY[:24]
            else:
                self.KEY = self.KEY[:32]
            print('Key shortened to "' + self.KEY + '"')
            
        with open(self.KEY_FILE, 'wb') as f:
            f.write(self.KEY)

    def getKey(self):
        if os.path.isfile(self.KEY_FILE):
            with open(self.KEY_FILE, 'rb') as f:
                byte = f.read(1)
                while byte:
                    self.KEY += byte
                    byte = f.read(1)
        else:
            self.makeKey()

if __name__ == '__main__':
    program = pyClipboardShare()
