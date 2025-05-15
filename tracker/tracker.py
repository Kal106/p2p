import json
import threading
import time
import requests
import hashlib
from datetime import datetime
from messages import Message
from handle_client import *
from parser import *
import socket
env_path = "./config.json"


RESGITER_MSG = "User Registered Successfully user can Login"
LOGIN_MSG = "User Logged in SuccesFully"
GROUP_CREATION_MSG = "Group created Successfully"
LOGOUT = "User Logged Out Successfully"
LEAVE_GRP = "User left Grp Successfully"

def hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

class Tracker:
    def __init__(self, tracker_id, tracker_addr):
        self.tracker_ip = tracker_addr["ip"]
        self.tracker_port = int(tracker_addr["port"])
        # self.all_trackers = all_trackers
        self.clients = set()
        self.lock = threading.Lock()
        self.running = True
        self.s = None
        self.active_clients = {}
        self.client_credentials = {}
        self.client_to_user = {}
        self.user_to_client = {}
        self.groups = {}
        self.grp_admin = {}
        self.grp_file = {}
        self.file_meta_data = {}
        self.user_data_chunk = {}
        self.chunk_user = {}
        self.group_file_chunk_Map = {}

    

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.tracker_ip, self.tracker_port))
        self.s = s
        self.s.listen(5)
        print(f"Running Tracker-{self.tracker_ip} at {self.tracker_port}")
        threading.Thread(target=self._track_clients).start()
        threading.Thread(target=self._command_listener, daemon=True).start()


    def check_if_user_is_logged(self, userId):
        return  self.active_clients.get(userId, False) is True
    
    def check_pass_word(self, userId, pass_word):
        return self.client_credentials[userId]["password"] == pass_word
    
    def activate_users_grps(self, userId):
        grps = self.client_credentials[userId]['grp']
        for grp in grps:
            if grp in self.groups and ('inactive' in self.groups[grp] and  userId in self.groups[grp]['inactive']):
                self.groups[grp]['inactive'].remove(userId)
                self.groups[grp].setdefault('active', set()).add(userId)

    
    def _handle_client_login(self, params, client_port, client_ip):
        userId = params["user_name"]
        password = params["password"]
        if userId not in self.active_clients:
            return getErrorResponse("Error", "User not Logged In")
        if not self.check_if_user_is_logged(userId):
            if self.check_pass_word(userId, password):
                self.active_clients[userId] = True
                self.client_credentials[userId]['ip'] = client_ip
                self.client_credentials[userId]['port'] = client_port
                addr = client_ip + ":" + client_port
                self.activate_users_grps(userId)
                self.client_to_user[addr] = userId
                self.user_to_client[userId] = addr
                return getResponse(LOGIN_MSG)
            return getErrorResponse("Password", "PassWord mismatch")
        return getErrorResponse("Duplicate Login", "User already Logged In")

                
    def _handle_register(self, userId, password):
        print("Active clinets: ", self.active_clients)
        print("User ID: ", userId)
        if userId in self.active_clients:
            return getErrorResponse("Duplicate User", "User already exists please use a different name")
        if self.check_if_user_is_logged(userId):
            return getErrorResponse("Duplicate Login", "user already logged in")
        self.active_clients[userId] = False
        self.client_credentials[userId] = {
            "password":password,
            "grp":set()
        }
        return getResponse(RESGITER_MSG)
    
    def check_if_grpExists(self, grpId):
        return grpId in self.groups


    def _handle_create_group(self, userId, grpId):
        if not self.check_if_user_is_logged(userId):
            return getErrorResponse("User", "User Not Logged In")
        if not self.check_if_grpExists(grpId):
            self.groups[grpId] = {"active": set(), "inactive": set()}
            self.grp_admin[grpId] = {
                "user" : userId,
                "request" : set()
            }

            self.client_credentials[userId]['grp'].add(grpId)
        self.groups[grpId]["active"].add(userId)
        return getResponse(GROUP_CREATION_MSG)
    

    def _handle_display_request(self, userId):
        grps = self.client_credentials[userId]['grp']
        requests = ""
        for grp in grps:
            if userId == self.grp_admin[grp]["user"]:
                reqs = self.grp_admin[grp]["request"]
                if reqs:
                    requests += f"Group {grp} requests: {', '.join(reqs)}\n"
        return getResponse(requests if requests else "No pending requests.")

    def _track_clients(self):
        while self.running:
            try:
                client_sock, addr = self.s.accept()
                data = client_sock.recv(1024).decode()
                client_listen_ip, client_listen_port = data.split(":")
                print(f"[INFO] Client is listening at {client_listen_ip}:{client_listen_port}")
                with self.lock:
                    self.clients.add(data)
                threading.Thread(target=self._handle_client, args=(client_sock, client_listen_ip, client_listen_port, addr)).start()
            except Exception as e:
                print(f"[ERROR] Accepting client failed: {e}")

    def _handle_join_group(self, userId, grpId):
        if not grpId in self.groups:
            return getResponse("No such grp with id: " + grpId + " Exists")
        if userId in self.groups[grpId]['active']:
            return getResponse("User is already in the group")
        if userId in self.grp_admin[grpId]['request']:
            return getResponse("User already raised the request")
        self.grp_admin[grpId]['request'].add(userId)
        return getResponse("Join request Raised successfully")

    def _check_if_user_is_loggedIn(self, client_ip, client_port):
        addr = client_ip + ":" + client_port
        if addr not in self.client_to_user:
            print("Nothing here")
            return False
        userId = self.client_to_user[addr]
        return self.check_if_user_is_logged(userId)
    
    def _handle_accept_to_group(self, adminId, newUserId, grpId):
        if  grpId not in self.grp_admin:
            return getErrorResponse("Group non-existence", "Group Doesnt exist")
        if self.grp_admin[grpId]['user'] != adminId:
            return getErrorResponse("InSufficient Privilidges", adminId + " :Doesnt have admin privilidges")
        if not newUserId in self.grp_admin[grpId]['request']:
            return getErrorResponse("No Join Request From User", newUserId + ": Didnt raise any request to join the group")
        if not self.check_if_user_is_logged(newUserId):
            self.groups[grpId]['inactive'].add(newUserId)
        else:
            print("He is active")
            self.groups[grpId]['active'].add(newUserId)
        self.grp_admin[grpId]['request'].remove(newUserId)
        self.client_credentials[newUserId]['grp'].add(grpId)
        return getResponse(newUserId + " :Accepted to grp: " + grpId)

    def _handle_leave_group(self, userId, grpId):
        user_params = self.groups[grpId]
        if userId in user_params['active']:
            user_params['active'].remove[userId]
        elif userId in user_params['inactive']:
            user_params['inactive'].remove[userId]
        if self.grp_admin[grpId]['user'] == userId:
            user_id_2 = next(iter(self.groups[grpId]['active']))
            self.grp_admin[grpId]['user'] = user_id_2
        return getResponse(LEAVE_GRP)
    
    def _handle_upload_file(self, userId, params):
        grpId = params["grpId"]
        file_path = params["filePath"]
        root_sha = params["merkleRoot"]
        key1 = hash_sha1(file_path + grpId)
        # self.getFiles_Sha[key1] = root_sha
        chunks_sha = params["chunksha"]

        # Ensure group and files exist
        if grpId not in self.groups:
            return getErrorResponse("Grp non-existence", f"Group with id {grpId} doesnt exist")

        if 'files' not in self.groups[grpId]:
            self.groups[grpId]['files'] = set()

        # Add file entry
        self.groups[grpId]['files'].add(file_path)

        key = hash_sha1(grpId + file_path)

        # Initialize user_data_chunk
        if userId not in self.user_data_chunk:
            self.user_data_chunk[userId] = {}

        if key not in self.user_data_chunk[userId]:
            self.user_data_chunk[userId][key] = []

        for chunk_sha in chunks_sha:
            self.user_data_chunk[userId][key].append(chunk_sha)

            # Track which users have which chunk
            chunk_key = hash_sha1(grpId + chunk_sha)
            if chunk_key not in self.chunk_user:
                self.chunk_user[chunk_key] = set()
            self.chunk_user[chunk_key].add(self.user_to_client[userId])
        json_ready_chunks = {
                k: list(v) for k, v in self.chunk_user.items()
            }
        self.group_file_chunk_Map[key] = {
            "chunks": json_ready_chunks,
            "rootSha": root_sha
            }
        return getResponse(f"Uploaded to Group: {grpId} Successfully")
    

    def _handle_download(self, userId, grpId, file_name):
        if grpId not in self.groups:
            return getErrorResponse("Grp Non existence", "Group doesn't exist")
        if userId not in self.groups[grpId]['active']:
            return getErrorResponse("No active user with id:", userId + " in this group")
        if file_name not in self.groups[grpId]['files']:
            return getErrorResponse("File not found", "No such file found in the group")

        key = hash_sha1(grpId + file_name)

        file_info = self.group_file_chunk_Map[key]
        chunks = file_info["chunks"]

        Message = {
            "file": file_name,
            "chunks": chunks,
        }

        return getResponse(Message)

        

    def _handle_client(self, client_sock, client_ip,client_port,addrr):
        with client_sock:
            accumulated_data = b""
            while self.running:
                try:
                    data = client_sock.recv(1024)
                    if not data:
                        print(f"[TRACKER] Client {addrr} disconnected.")
                        self._handle_clientLogout(client_ip, str(client_port))
                        break
                    accumulated_data += data
                    try:
                        json_data = json.loads(accumulated_data.decode().strip())
                        print(f"[TRACKER] Received from {addrr}: {json_data}")
                        accumulated_data = b""
                        if not checkFormat(json_data):
                            response = getErrorResponse("format_error", "Incorrect Json Format")
                        else:
                            cmd = json_data["type"]
                            params = json_data["params"]
                            if cmd != "register" and cmd != "login" and self._check_if_user_is_loggedIn(client_ip, str(client_port)):
                                userId = self.client_to_user[client_ip + ":"+str(client_port)]
                                print("User id: ", userId)
                                if cmd == "list_groups":
                                    grps = self.groups.keys()
                                    msgs = ""
                                    for grp in grps:
                                        msgs += grp
                                        msgs += "\n"
                                    response = getResponse(msgs)
                                elif cmd == "list_requests":
                                   response =  self._handle_display_request(userId)
                                elif cmd == "join_group":
                                   response =  self._handle_join_group(userId, params['grpId'])
                                elif cmd == "create_group":
                                    response =  self._handle_create_group(userId, params['grpId'])
                                elif cmd == "leave_group":
                                    response = self._handle_leave_group(userId, params['grpId'])
                                elif cmd == "accept":
                                    response = self._handle_accept_to_group(userId, params["user"], params["grpId"])
                                elif cmd == "upload":
                                    response = self._handle_upload_file(userId, params)
                                elif cmd == "download":
                                    response = self._handle_download(userId, params['grpId'], params['file_name'])
                                else:
                                    response = getErrorResponse("Invalid Command", cmd + " :is Invalid")
                            elif cmd == "register":
                                userId = params["user_name"]
                                password = params["password"]
                                response = self._handle_register(userId, password)
                            elif cmd == "login":
                                response = self._handle_client_login(params, str(client_port), client_ip)
                            else:
                                response = getErrorResponse("Login Error","User is not Logged In")
                        print("response sent: ", response)
                        client_sock.sendall(json.dumps(response).encode())
                    except json.JSONDecodeError:
                        continue
                except Exception as e:
                    print(f"[ERROR] Handling client {addrr}: {e}")
                    break


    def _command_listener(self):
        while self.running:
            cmd = input("Enter command (stop/rtc): ").strip().lower()
            if cmd == "stop":
                print("Stopping tracker...")
                self.running = False
                break
            elif cmd == "rtc":
                print("Tracked clients:")
                for client in self.get_clients():
                    print(client)
            elif cmd == "get":
                print("Active clinets:")
                print(self.active_clients)
            else:
                print("Unknown command. Available commands: stop, rtc")
    def _handle_clientLogout(self, client_ip, client_port):
        addr = client_ip + ":" + client_port
        if not addr in self.client_to_user:
            return getResponse(LOGOUT)
        userId = self.client_to_user[addr]
        self.active_clients[userId] = False
        grps = self.client_credentials[userId]['grp']
        for grp in grps:
            self.groups[grp]["active"].remove(userId)
            self.groups[grp]["inactive"].add(userId)
        return getResponse(LOGOUT)

    def get_clients(self):
        with self.lock:
            return list(self.clients)

def load_config_and_start():
    with open(env_path, 'r') as f:
        config = json.load(f)

    trackers = config["trackers"]

    while True:
        try:
            tracker_num = int(input("Enter tracker number to run: ").strip())
            break
        except ValueError:
            print("Error: Invalid input for tracker number. Please enter a valid integer.")


    if tracker_num <= 0 or tracker_num > len(trackers):
        print("Invalid tracker number.")
        return

    tracker_addr = trackers[tracker_num-1]
    tracker = Tracker(tracker_num, tracker_addr)
    tracker.run()

if __name__ == "__main__":
    try:
        load_config_and_start()
    except ValueError:
        print("Value Error")
