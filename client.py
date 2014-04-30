import socket
import Tkinter
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

client_fixed_hash = "b79da5640ba0e9b393f7922aac597fd1"

lib = []
auth_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
#get authtoken for data transaction
def get_auth_token():

    auth_server.connect(("127.0.0.1", 56789))
    auth_server.send(client_fixed_hash)
    authentication_token = auth_server.recv(1024)
    auth_token = (authentication_token, True)

    print auth_token

    return auth_token

auth_token = get_auth_token()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
server_socket.connect(("127.0.0.1", 12356))
server_socket.send(auth_token[0]+"\n"+"Hello")
#get auth token
#setup encryption
GET_ENCODE_KEY = open("pubkey_client_encode.pem", "r")
encode_key = RSA.importKey(GET_ENCODE_KEY.read())

#setup cipher
cipher = PKCS1_OAEP.new(encode_key)

#setup decryption
GET_DECODE_KEY = open("pvtkey_client_decode.pem", "r")
decode_key = RSA.importKey(GET_DECODE_KEY.read())

#setup decypher
decipher = PKCS1_OAEP.new(decode_key)


print "Auth token received :", auth_token[0]


def get_from_server(text_area, server_socket):

    while True:

        message = server_socket.recv(1024)
        print message

        message = decipher.decrypt(message)
        text_area.insert(Tkinter.INSERT, message)
        text_area.insert(Tkinter.INSERT, "\n\n\n")


def send_to_server():

    print E1.get()

    plain_text = auth_token[0] + "\n" + E1.get()

    print "plain text: ", plain_text
    cipher_text = cipher.encrypt(plain_text)

    print cipher_text

    text_area.insert(Tkinter.INSERT, E1.get())

    text_area.insert(Tkinter.INSERT, "\n\n\n")

    server_socket.send(cipher_text)

    E1.delete(0, len(E1.get()))


# Setup TKinter UI
top = Tkinter.Tk()
text_area = Tkinter.Text(top)

text_area.pack(side=Tkinter.TOP)

E1 = Tkinter.Entry(top, bd=5, width = 100)

E1.pack(side=Tkinter.RIGHT)

button_send = Tkinter.Button(top, text="Send Message!", command=send_to_server)
button_send.pack(side=Tkinter.RIGHT)


th = Thread(target=get_from_server, args=(text_area, server_socket,))
th.start()
lib.append(th)

top.mainloop()
#End Tkinter UI


