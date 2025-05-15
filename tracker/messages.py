
class Message:
    def __init__(self, tracker_details):
        self.tracker_ip = tracker_details.ip
        self.tracker_port = tracker_details.port
        self.register_msg = {
            "type": "register",
            # "tracker_id": tracker_id,
            "ip": tracker_details.ip,
            "port": tracker_details.port
        }
        self.update_msg = {
            "type": "update_clients",
            "clients": tracker_details.clients
        }

        # Get All Clients
        self.get_msg = {
            "type": "get_all_clients"
        }