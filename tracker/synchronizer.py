import socket
import threading
import json

registered_trackers = {}
lock = threading.Lock()

def handle_client(conn, addr):
    while True:
        try:
            data = conn.recv(4096).decode()
            if not data:
                break
            msg = json.loads(data)

            if msg["type"] == "register":
                with lock:
                    registered_trackers[msg["tracker_id"]] = {
                        "ip": msg["ip"],
                        "port": msg["port"],
                        "clients": []
                    }
                conn.sendall(b"registered")

            elif msg["type"] == "update_clients":
                with lock:
                    if msg["tracker_id"] in registered_trackers:
                        registered_trackers[msg["tracker_id"]]["clients"] = msg["clients"]
                        conn.sendall(b"clients updated")
                    else:
                        conn.sendall(b"tracker not registered")

            elif msg["type"] == "get_all_clients":
                all_clients = set()
                with lock:
                    for info in registered_trackers.values():
                        all_clients.update(info["clients"])
                response = json.dumps(list(all_clients))
                conn.sendall(response.encode())

        except Exception as e:
            print(f"Error: {e}")
            break

    conn.close()


def run_sync_server(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen(5)
    print(f"[Synchronizer] Listening on {ip}:{port}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    run_sync_server("127.0.0.1", 9000)
