import socket
from datetime import datetime
from threading import Thread
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class Server:

    # CLIENT_SOCKETS holds hash and socket object
    CLIENT_SOCKETS = []
    CIPHER_KEYS = []
    CLIENT_AUTH_HASHES = []
    THREADS = []
    THREAD_SIGNALS = []
    SHELL_FUNCTIONS = {}

    connection_limit = 10
    logfile = open("logs/log.txt", "a")
    thread_log = open("logs/thread_log.txt", "a")

    key_1 = open("Keys/pvtkey_server_decode.pem", "r")
    key_2 = open("Keys/pubkey_server_encode.pem", "r")

    decrypt_client_traffic = RSA.importKey(key_1.read())
    encrypt_server_reply = RSA.importKey(key_2.read())

    #cipher and decipher setup
    decipher = PKCS1_OAEP.new(decrypt_client_traffic)
    cipher = PKCS1_OAEP.new(encrypt_server_reply)

    #constructor
    def __init__(self):

        start_message = "Started server instance @"+str(datetime.now())
        self.logfile.write(start_message)
        self.logfile.write("\n")

        print "Reading Keys to Memory"
        key_1 = open("Keys/pvtkey_server_decode.pem", "r")
        key_2 = open("Keys/pubkey_server_encode.pem", "r")

        self.CIPHER_KEYS.append(key_1.read())
        self.CIPHER_KEYS.append(key_2.read())

        key_1.close()
        key_2.close()

        #remove physical keys
        key_1 = open("Keys/pvtkey_server_decode.pem", "w")
        key_2 = open("Keys/pubkey_server_encode.pem", "w")

        key_1.close()
        key_2.close()

        self.setup_server()

    def setup_server(self):

        stop_listening = threading.Event()
        self.THREAD_SIGNALS.append(stop_listening)
        listen_ = Thread(target=self.listen_for_clients, args=(stop_listening,), name="listen_for_clients_thread")
        listen_.start()
        self.THREADS.append(listen_)

        # Do not append shell() thread to THREADS
        # as we iterate through it to kill all threads late
        # I.e, we don't want the thread to kill itself
        print "\nSetting Up Shell\n"
        self.SHELL_FUNCTIONS["kill"] = self.kill
        self.SHELL_FUNCTIONS["list"] = self.view_clients

        print "\nStarting Shell\n"
        shell = Thread(target=self.shell, args=(), name="shell_thread")
        shell.setDaemon(True)
        shell.start()

    def shell(self):

        while True:
            command = raw_input()
            if command == "kill":
                break
            self.SHELL_FUNCTIONS[command]()

        self.kill()

    def kill(self):
    #disconnect all clients
        print "Shutting Down\n"
        for CLIENT in self.CLIENT_SOCKETS:
            #closing all sockets
            CLIENT[1].send("~kill")
            CLIENT[1].close()

    #rewrite keys to HDD
        print "Writing Keys to File"
        key_1 = open("Keys/pvtkey_server_decode.pem", "a")
        key_2 = open("Keys/pubkey_server_encode.pem", "a")
        key_1.write(self.CIPHER_KEYS[0])
        key_2.write(self.CIPHER_KEYS[1])
        print "DONE Writing Keys to File"
        key_1.close()
        key_2.close()


    #signal all threads
        print "Signalling threads to end"
        for SIGNAL in self.THREAD_SIGNALS:

            SIGNAL.set()

    #check for threads that are alive
        print "Popping dead Threads"
        for THREAD in self.THREADS:

            if not(THREAD.is_alive()):
                print "Removing dead thread : "+str(THREAD.getName())
                self.THREADS.remove(THREAD)

        print threading.active_count()

        for THREAD in self.THREADS:

            print THREAD.getName()

    def view_clients(self):

        print "\n-------List of Clients-------------\n"

        print str(len(self.CLIENT_SOCKETS))+" Clients connected\n"

        for SOCK in self.CLIENT_SOCKETS:

            print str(SOCK[0])+" @ "+str(SOCK[1])

        print "\n-------End Client List------------\n"

    #verify client hash against CLIENT_AUTH_HASHES
    def verify_client(self, client_hash):

        print "Verifying client hash :", client_hash

        client_is_valid = False

        if client_hash == "4b6ba45469bac26bdd9d49574b65132e":

            client_is_valid = "auth_server"

        else:

            for client_hash_match in self.CLIENT_AUTH_HASHES:

                if client_hash_match == client_hash:

                    client_is_valid = True

        print "Client Validity : ", client_is_valid
        return client_is_valid

    #sends message to all clients except client_socket
    def send_to_all_clients(self, message, client_socket):

        for cli_socket in self.CLIENT_SOCKETS:

            if cli_socket != client_socket:

                cli_socket[1].send(message)

    #closes and removes client from CLIENT_SOCKETS
    def kill_client_connection(self, client_hash):

        self.CLIENT_AUTH_HASHES.remove(client_hash)

        for client in self.CLIENT_SOCKETS:

            if client[0] == client_hash:

                client[1].close()

                self.CLIENT_SOCKETS.remove(client)

                print client_hash, "Has been Removed"

    def send_to_client(self, cli_socket, message):

        message = self.cipher.encrypt(message)
        cli_socket.send(message)

    def listen_to_client(self, cli_socket, stop_signal):

        while not(stop_signal.is_set()):

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
                break

        if stop_signal.is_set():
            cli_socket.close()
            print "Signalled to Stop\n"


    def auth_server_get_hash(self, auth_server_socket, stop_signal):

        while not(stop_signal.is_set()):

            client_hash = auth_server_socket.recv(1024)
            print "Received hash from auth server : ", client_hash
            print "Length : ", len(client_hash)
            self.CLIENT_AUTH_HASHES.append(client_hash)

        if stop_signal.is_set():

            auth_server_socket.close()
            print "Signalled To Stop\n"


    def setup_welcome_thread(self):

        welcome_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        welcome_socket.bind(("127.0.0.1", 12356))
        welcome_socket.listen(self.connection_limit)

        print "Welcome Socket created"

        return welcome_socket

    def listen_for_clients(self, stop_signal):

        welcome_socket = self.setup_welcome_thread()

        while (self.connection_limit != 0) and not(stop_signal.is_set()):

            client_socket, data = welcome_socket.accept()

            self.logfile.write("\n")
            self.logfile.write(str(data))
            self.logfile.write("\n")

            client_auth_hash = client_socket.recv(1024)

            client_auth_hash = client_auth_hash.split("\n")

            client_auth_hash = client_auth_hash[0]

            print "Received hash from client:", client_auth_hash
            print "Length : ", len(client_auth_hash)

            if self.verify_client(client_auth_hash) == "auth_server":

                stop_auth_server = threading.Event()
                self.THREAD_SIGNALS.append(stop_auth_server)
                auth_server_get_hash_thread = Thread(target=self.auth_server_get_hash, args=(client_socket, stop_auth_server,), name="auth_server")

                auth_server_get_hash_thread.start()

                self.THREADS.append(auth_server_get_hash_thread)

                self.connection_limit -= 1

            if self.verify_client(client_auth_hash) == True:

                print "Client has authenticated"

                self.CLIENT_AUTH_HASHES.append(client_auth_hash)

                client_id = (client_auth_hash, client_socket)
                self.CLIENT_SOCKETS.append(client_id)

                stop_client_recv_thread = threading.Event()
                self.THREAD_SIGNALS.append(stop_client_recv_thread)
                recv_thread = Thread(target=self.listen_to_client, args=(client_socket, stop_client_recv_thread,), name="client_thread")
                #recv_thread.setDaemon(True)
                recv_thread.start()

                self.THREADS.append(recv_thread)

                self.connection_limit -= 1

            else:

                client_socket.send("Failed to auth")

        print "\nWelcome Thread has Ended\n"

if __name__ == "__main__":

    server_instance = Server()


