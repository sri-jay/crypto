import socket
from datetime import datetime
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import Tkinter


class Server:

    CLIENT_SOCKETS = []
    CLIENT_AUTH_HASHES = []
    THREADS = []

    connection_limit = 10
    logfile = open("log.txt", "w")
    thread_log = open("thread_log.txt", "w")

    key_1 = open("pvtkey_server_decode.pem", "r")
    key_2 = open("pubkey_server_encode.pem", "r")

    decrypt_client_traffic = RSA.importKey(key_1.read())
    encrypt_server_reply = RSA.importKey(key_2.read())

    decipher = PKCS1_OAEP.new(decrypt_client_traffic)
    cipher = PKCS1_OAEP.new(encrypt_server_reply)

    def __init__(self):

        start_message = "Started server instance @"+str(datetime.now())
        self.logfile.write(start_message)
        self.logfile.write("\n")

        listen_ = Thread(target=self.listen_for_clients(), args=())
        listen_.start()
        self.THREADS.append(listen_)


        #self.listen_for_clients()
    def verify_client(self, client_hash):

        print "Verifying client hash :", client_hash

        client_is_valid = False

        if client_hash == "4b6ba45469bac26bdd9d49574b65132e":

            client_is_valid = "auth_server"

        else:

            for client_hash_match in self.CLIENT_AUTH_HASHES:

                print "Length 1 ", len(client_hash_match)
                print "Length 2 ", len(client_hash)

                if client_hash_match == client_hash:

                    client_is_valid = True

        print "Client Validity : ",client_is_valid
        return client_is_valid


    def send_to_all_clients(self, message, client_socket):

        for cli_socket in self.CLIENT_SOCKETS:

            if cli_socket != client_socket:

                cli_socket[1].send(message)


    def kill_client_connection(self, client_hash):

        for client in self.CLIENT_SOCKETS:

            if client[0] == client_hash:

                client[1].close()

                self.CLIENT_SOCKETS.remove(client)


    def send_to_client(self, cli_socket, message):

        message = self.cipher.encrypt(message)
        cli_socket.send(message)

    def listen_to_client(self, cli_socket):

        while True:

            encrypted_data = cli_socket.recv(1024)
            clear_data = self.decipher.decrypt(encrypted_data)

            client_message = clear_data.rstrip().split("\n")

            client_hash = client_message[0]

            print client_message[1]

            if self.verify_client(client_hash):

                message = self.cipher.encrypt(client_message[1])

                self.send_to_all_clients(message, cli_socket)

            else:

                cli_socket.send("You are not Authenticated, Closing connection")
                self.kill_client_connection(client_hash)

    def auth_server_get_hash(self, auth_server_socket):

        while True:

            client_hash = auth_server_socket.recv(1024)
            print "Received hash from auth server : ", client_hash
            print "Length : ",len(client_hash)
            self.CLIENT_AUTH_HASHES.append(client_hash)


    def setup_welcome_thread(self):

        welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        welcome_socket.bind(("127.0.0.1", 12356))
        welcome_socket.listen(self.connection_limit)

        return welcome_socket

    def listen_for_clients(self):

        welcome_socket = self.setup_welcome_thread()

        while self.connection_limit != 0:

            print self.connection_limit

            client_socket, data = welcome_socket.accept()

            self.logfile.write("\n")
            self.logfile.write(str(data))
            self.logfile.write("\n")

            client_auth_hash = client_socket.recv(1024)

            client_auth_hash = client_auth_hash.split("\n")

            client_auth_hash = client_auth_hash[0]

            print "Received hash from client:",client_auth_hash
            print "Length : ",len(client_auth_hash)

            if self.verify_client(client_auth_hash) == "auth_server":

                auth_server_get_hash_thread = Thread(target=self.auth_server_get_hash, args=(client_socket, ))
                auth_server_get_hash_thread.start()

                self.THREADS.append(    auth_server_get_hash_thread)

                self.connection_limit -= 1

            if self.verify_client(client_auth_hash) == True:

                print "Client has authenticated"

                self.CLIENT_AUTH_HASHES.append(client_auth_hash)

                client_id = (client_auth_hash, client_socket)
                self.CLIENT_SOCKETS.append(client_id)

                recv_thread = Thread(target=self.listen_to_client, args=(client_socket, ))
                recv_thread.start()

                self.THREADS.append(recv_thread)

                self.connection_limit -= 1

            else:

                client_socket.send("Failed to auth")

if __name__ == "__main__":

    server_instance = Server()


