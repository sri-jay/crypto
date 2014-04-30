import socket
from Crypto import Random
from Crypto.Hash import MD5
from datetime import datetime

#creating logfile
log = open("auth_server_log.txt", "w")

#auth start log
log_data = "Started Auth Server @"+str(datetime.now())+"\n"
log.write(log_data)
#end logging

#fixed auth hash which each client must pass to auth server to recive authentication_hash
auth_hash = "4b6ba45469bac26bdd9d49574b65132e"
clients = []

#creating sockets to accept clients and report to server
client_welcome = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
server_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

#connecting to server andd setup client sockets
server_auth.connect(("127.0.0.1", 12356))
client_welcome.bind(("127.0.0.1", 56789))
client_welcome.listen(10)

#authenticating self to Server
server_auth.send(auth_hash)

#auth log
log_data = str(datetime.now()) + " : "+"registered with Server @"+str(datetime.now())+"\n"
log.write(log_data)
#end log

#accepting clients and verifyting their identitiy
while True:

    client_socket, client_data = client_welcome.accept()

    #get client_fixed_hash
    client_hash = client_socket.recv(1024)
    print "Client attempting to connect with hash: ", client_hash

    #loggging start
    log_data = str(datetime.now()) + " : " + "Attempt To connect with hash : "+client_hash+"\n"
    log.write(log_data)
    #logging end

    #verifying client hash
    if client_hash == "b79da5640ba0e9b393f7922aac597fd1":

        #create client_auth_token
        client_auth_token = MD5.new(Random.get_random_bytes(256)).hexdigest()
        client_id = (client_socket, client_data, client_hash, client_auth_token)

        clients.append(client_id)

        #send auth tokens to client and server
        client_socket.send(client_auth_token)
        server_auth.send(client_auth_token)

        print "Client has authenticated, sending client auth token: ", client_auth_token

        #logging begin
        log_data = str(datetime.now())+" : "+client_auth_token+" has authenticated " + "\n"
        log.write(log_data)
        #logging end

    else:

        #logging start
        log_data = str(datetime.now())+" : "+client_hash+" has failed authentication"+"\n"
        #logging end

        client_socket.send("Invalid hash, you are being disconnected")
        client_socket.close()

