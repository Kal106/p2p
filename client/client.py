import socket
import threading
import hashlib
import json
import os
import ast
from concurrent.futures import ThreadPoolExecutor
from parser import *
import random
import time


CHUNK_SIZE =  512 * 1024

def hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()


class ClientDetails:
    def __init__(self, ip=None, port=None):
        self.ip = ip if ip else "127.0.0.1"
        self.port = port if port else "7887"


class Client:
    def __init__(self, client_details):
        self.client_ip = client_details.ip
        self.client_port = int(client_details.port)
        self.groups = {}
        self.file_chunks = {}
        self.downloadable_chunks = {}
        self.running = True
        self.tracker_ip, self.tracker_port = self._load_tracker_from_config()
        self.tracker_socket = None
        self.user_name = None
        self.password = None
        self.file_meta ={}
        self.index_sha_map = {}


    def _load_tracker_from_config(self):
        with open("../tracker/config.json", "r") as f:
            config = json.load(f)
        tracker = config["trackers"][0]
        return tracker["ip"], int(tracker["port"])
    
    def connect_to_tracker(self):
        try:
            self.tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tracker_socket.connect((self.tracker_ip, self.tracker_port))
            self.tracker_socket.send(f"{self.client_ip}:{self.client_port}".encode())
            print(f"Connected to tracker at {self.tracker_ip}:{self.tracker_port}")
            return True
        except Exception as e:
            print(f"Error connecting to tracker: {e}")
            return False

    def handle_register(self):
        user_id = input("Enter user id to register: ").strip()
        password = input("Enter password for the account: ").strip()
        password = hash_sha1(password)
        message = {
            "type": "register",
            "params": {
            "user_name": user_id,
            "password": password
            }
        }

        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            response = json.loads(response)
            if response['status'].lower() == 'error':
                print(response['type'] + " " + response['message'])
            else:
                print("Tracker response:", response["message"])
        except Exception as e:
            print("Error communicating with tracker:", e)

    def handle_login(self):
        user_id = input("Enter user id to login: ").strip()
        password_u = input("Enter password: ").strip()
        password = hash_sha1(password_u)
        message = {
            "type": "login",
            "params": {
                "user_name": str(user_id),
                "password": password
            }
        }
        
        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
            self.user_name = user_id
        except Exception as e:
            print("Error communicating with tracker:", e)


    def handle_logout(self):
        print("..Logging_out..")
        if self.tracker_socket:
            try:
                self.tracker_socket.close()
                print("Disconnected from tracker")
            except Exception as e:
                print("Error closing tracker connection:", e)

    def _handle_create_group(self):
        grpId = input("Enter the group you want to create: ").strip()
        message = {
            "type": "create_group",
            "params": {
                "grpId":grpId
            }
        }
        
        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error communicating with tracker:", e)

    def _handle_join_group(self):
        grpId = input("Enter the group you want to join: ").strip()
        message = {
            "type": "join_group",
            "params": {
                "grpId":grpId
            }
        }
        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error communicating with tracker:", e)
    
    def _list_groups(self):
        message = {
            "type":"list_groups",
            "params": None
        }

        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error communicating with tracker:", e)

    def _list_requests(self):
        message = {
            "type":"list_requests",
            "params": None
        }

        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error communicating with tracker:", e)
    
    def _leave_group(self):
        grpId = input("Enter the group you want to leave: ").strip()
        message = {
            "type":"list_requests",
            "params": {
                "grpId":grpId
            }
        }

        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error communicating with tracker:", e)
    
    def handle_accept(self):
        grpId = input("Enter the group you want to check: ").strip()
        newUserId = input("Enter the user you want to accept into group").strip()
        message = {
            "type":"accept",
            "params": {
                "grpId":grpId,
                "user": newUserId
            }
        }
        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error communicating with tracker:", e)
    
    def _reassemble_the_chunks(self, file):
        try:
            output_path = f"reconstructed_{file}"
            with open(output_path, "wb") as output_file:
                for index in sorted(self.index_sha_map[file].keys()):
                    sha = self.index_sha_map[file][index]
                    chunk_path = f"chunks/{sha}.chunk"
                    if not os.path.exists(chunk_path):
                        print(f"❌ Missing chunk: {chunk_path}")
                        return
                    with open(chunk_path, "rb") as chunk_file:
                        output_file.write(chunk_file.read())

            print(f"🧩 Successfully reassembled file to {output_path}")
        except Exception as e:
            print(f"❌ Error while reassembling file {file}: {e}")


    
    def download_chunk(self, sha, ip, port, file):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                request = json.dumps({"file": file, "sha": sha})
                s.sendall(request.encode())

                buffer = b""
                while True:
                    byte = s.recv(1)
                    if not byte:
                        raise Exception("Connection closed while reading header")
                    buffer += byte
                    try:
                        msg = json.loads(buffer.decode())
                        break
                    except json.JSONDecodeError:
                        continue

                index = msg["index"]
                print(f"📥 Received index {index} from {ip}:{port}")
                self.index_sha_map.setdefault(file, {})[index] = sha

                chunk_data = b""
                while True:
                    try:
                        data = s.recv(4096)
                        if not data:
                            break
                        chunk_data += data
                    except socket.timeout:
                        break

                os.makedirs("chunks", exist_ok=True)
                with open(f"chunks/{sha}.chunk", "wb") as f:
                    f.write(chunk_data)

                print(f"✅ Downloaded chunk {sha} from {ip}:{port}")
                time.sleep(0.1)
            self._reassemble_the_chunks(file)

        except socket.timeout:
            print(f"❌ Timeout while connecting to {ip}:{port}")
        except json.JSONDecodeError:
            print(f"❌ Failed to decode JSON from {ip}:{port}")
        except Exception as e:
            print(f"❌ General error from {ip}:{port}: {e}")


    def start_downloading_chunks(self, chunk_map, file, max_workers=50):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for sha, (ip, port) in chunk_map.items():
                executor.submit(self.download_chunk, sha, ip, port, file)
        

    def handle_download(self):
        grpId = input("Enter the group you want to download the file from: ").strip()
        file = input("Enter the file_path/name you to download: ").strip()
        path = input("Enter the destination of your download: ").strip()
        message = {
            "type": "download",
            "params": {
                "grpId": grpId,
                "file_name": file
            }
        } 
        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response =  self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
            response_json = json.loads(response)
            message = response_json['message']
            file = message["file"]
            message = message["chunks"]
            self._connect_to_clients_to_downloads(message, file)

        except Exception as e:
            print("Error communicating with Tracker: ", e)

    def _connect_to_clients_to_downloads(self, message, file):
        selected_peers = {}

        for sha, peer_list in message.items():
            if not peer_list:
                print(f"❌ No peers available for chunk {sha}")
                continue
            chosen = random.choice(peer_list)

            ip, port = chosen.split(":")
            selected_peers[sha] = (ip, int(port))

        self.start_downloading_chunks(selected_peers, file)
        
        


    def handle_upload(self):
        file_path = input("Enter the path of the file you want to upload: ").strip()
        grpId = input("Enter the group you want to upload the file to: ").strip()

        chunk_size = CHUNK_SIZE
        chunks_meta, chunk_hashes = split_file_into_chunks(file_path, chunk_size, grpId)
        if not chunks_meta:
            print("File chunking failed.")
            return

        merkle_root = compute_merkle_root(chunk_hashes)
        self.file_meta[file_path] = chunks_meta

        message = {
            "type": "upload",
            "params": {
                "filePath": os.path.basename(file_path),
                "grpId": grpId,
                "chunkSize": chunk_size,
                "chunksha": chunk_hashes,
                "merkleRoot": merkle_root
            }
        }

        try:
            self.tracker_socket.sendall(json.dumps(message).encode())
            response = self.tracker_socket.recv(4096).decode()
            print("Tracker response:", response)
        except Exception as e:
            print("Error in communicating with tracker:", e)

    def _handle_chunk_request(self, conn, addr):
        try:
            raw = conn.recv(1024).decode().strip()
            request = json.loads(raw)
            file_name = request["file"]
            sha = request["sha"]

            print(f"📥 Request for chunk {sha} from file {file_name} by {addr}")

            chunk_info = None
            if file_name in self.file_meta:
                chunk_info = self.file_meta[file_name].get(sha)

            if not chunk_info:
                print(f"❌ Chunk {sha} not found in file {file_name}")
                return

            start = chunk_info["start"]
            end = chunk_info["end"]
            index = chunk_info["index"]
            msg = {"index": index}

            try:
                conn.sendall((json.dumps(msg)).encode())
            except BrokenPipeError:
                print(f"❌ Client at {addr} closed connection before header was sent.")
                return

            try:
                with open(f"./{file_name}", "rb") as f:
                    f.seek(start)
                    bytes_to_send = end - start + 1
                    while bytes_to_send > 0:
                        data = f.read(min(4096, bytes_to_send))
                        if not data:
                            break
                        conn.sendall(data)
                        bytes_to_send -= len(data)
            except (BrokenPipeError, ConnectionResetError) as e:
                print(f"❌ Client {addr} disconnected during transfer: {e}")
                return

            print(f"📤 Sent chunk {sha} ({start}-{end}) of {file_name} to {addr}")

        except Exception as e:
            print(f"❌ Error serving chunk to {addr}: {e}")
        finally:
            conn.close()





    def _serve_chunks(self, server_socket):
        while self.running:
            try:
                conn, addr = server_socket.accept()
                threading.Thread(target=self._handle_chunk_request, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")



    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((self.client_ip, self.client_port))
            s.listen(5)
            print(f"Running Client at {self.client_ip}:{self.client_port}")
            if not self.connect_to_tracker():
                print("Failed to connect to tracker. Exiting.")
                return 
            threading.Thread(target=self._serve_chunks, args=(s,), daemon=True).start()
            listener_thread = threading.Thread(target=self._command_listener, daemon=True)
            listener_thread.start()
            listener_thread.join()
            s.close()
        except Exception as e:
            print("Unable to start the client", e)

    def _command_listener(self):
        while self.running:
            try:
                cmd = input("Enter command: ").strip().lower()
                if cmd == "stop":
                    self.handle_logout()
                    self.running = False
                elif cmd == "login":
                    self.handle_login()
                elif cmd == "register":
                    self.handle_register()
                elif cmd == "create_group":
                    self._handle_create_group()
                elif cmd == "join_group":
                    self._handle_join_group()
                elif cmd == "list_groups":
                    self._list_groups()
                elif cmd == "list_requests":
                    self._list_requests()
                elif cmd == "leave_group":
                    self._leave_group()
                elif cmd == "logout":
                    self.handle_logout()
                elif cmd == "accept":
                    self.handle_accept()
                elif cmd == "upload":
                    self.handle_upload()
                elif cmd == "download":
                    self.handle_download()
                else:
                    print("Unknown command. Available commands: login, register, stop")
            except KeyboardInterrupt:
                self.handle_logout()
                self.running = False


if __name__ == "__main__":
    ip = input("Enter client IP (e.g. 127.0.0.1): ").strip()
    port = input("Enter client port (e.g. 5000): ").strip()
    client_details = ClientDetails(ip, port)
    client = Client(client_details)
    client.run()
