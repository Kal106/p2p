
# 📡 P2P File Sharing System

A peer-to-peer (P2P) file sharing system built in Python that enables distributed file uploads and downloads across multiple clients with a centralized tracker for coordination.

## 🚀 Features

* User registration and login with hashed passwords
* Group-based file sharing
* File upload with chunking and Merkle root hashing
* File download with parallel chunk retrieval from peers
* Tracker-managed metadata for users, groups, and files
* Dynamic peer selection for file chunk download
* Tracker synchronization system for multiple tracker setups

## 🗂️ Project Structure

```
.
├── client.py         # P2P client code (register, login, upload, download)
├── tracker.py        # Tracker server to manage groups, files, and clients
├── parser.py         # File chunking and hash utilities
├── messages.py       # Tracker registration/update message structure
├── synchronizer.py   # Multi-tracker sync server
├── config.json       # Tracker configuration
└── chunks/           # Stores individual file chunks
```

## ⚙️ Setup Instructions

### 1. Requirements

* Python 3.7+
* Standard libraries used: `socket`, `threading`, `hashlib`, `json`, `os`

### 2. Configure Trackers

Update `config.json` with tracker details:

```json
{
  "trackers": [
    {
      "ip": "127.0.0.1",
      "port": "8080"
    },
    {
      "ip": "127.0.0.1",
      "port": "8081"
    }
  ]
}
```

### 3. Start Synchronizer (Optional, for multiple trackers)

```bash
python3 synchronizer.py
```

### 4. Run Tracker

```bash
python3 tracker.py
```

You will be prompted to enter the tracker number (based on `config.json`).

### 5. Run Client

```bash
python3 client.py
```

You'll be asked to enter the client IP and port.

## 🧪 Supported Commands (Client Side)

* `register` – Register a new user
* `login` – Login with existing credentials
* `create_group` – Create a new group
* `join_group` – Send join request to group
* `accept` – Group admin accepts a join request
* `upload` – Upload and share a file to a group
* `download` – Download file from group peers
* `list_groups` – List available groups
* `list_requests` – View group join requests (admin only)
* `leave_group` – Leave a joined group
* `logout` – Logout from system
* `stop` – Exit the client

## 📦 File Upload Process

1. File is split into fixed-size chunks (512 KB).
2. Each chunk is hashed using SHA-256.
3. Merkle root is computed for the file.
4. Metadata is sent to the tracker for indexing.

## 📥 File Download Process

1. Client requests tracker for file metadata and chunk location.
2. Peers are randomly selected per chunk.
3. Chunks are downloaded in parallel.
4. Chunks are reassembled into the original file.

## 🔐 Security

* Passwords are stored and compared using SHA-1 hashes.
* File and chunk integrity verified via SHA-256 and Merkle roots.

## 📎 Notes

* Ensure all clients and trackers are on the same local network or have accessible ports.
* Chunked files are stored temporarily in the `chunks/` directory.

