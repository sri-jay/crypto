import socket
from Crypto import Random
from Crypto.Hash import MD5
from threading import Thread

auth_hash = "4b6ba45469bac26bdd9d49574b65132e"
clients = []

client_welcome = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
server_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

server_auth.connect(("127.0.0.1", 12356))
client_welcome.bind(("127.0.0.1", 56789))
client_welcome.listen(10)

server_auth.send(auth_hash)
while True:

    client_socket, client_data = client_welcome.accept()

    client_hash = client_socket.recv(1024)
    print "Client attempting to connect with hash: ", client_hash

    if client_hash == "b79da5640ba0e9b393f7922aac597fd1":

        client_auth_token = MD5.new(Random.get_random_bytes(256)).hexdigest()
        client_id = (client_socket, client_data, client_hash, client_auth_token)

        clients.append(client_id)

        client_socket.send(client_auth_token)
        server_auth.send(client_auth_token)

        print "Sending client auth token: ", client_auth_token

    else:

        client_socket.close()

