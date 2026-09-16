"""One shared hostlist and transparent spectator UDP relay for all lobby processes.

Lobby processes publish complete snapshots to loopback UDP/18081. The public
HTTP endpoint keeps the existing /games shape; each started game gets a public
UDP port. Game datagrams are not decoded or modified.
"""

import argparse
import hmac
import ipaddress
import json
import selectors
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SNAPSHOT_TTL = 12
VIEWER_TTL = 90
HOST_TTL = 900
MAX_VIEWERS = 64
MAX_TOTAL_VIEWERS = 512
MAX_PACKET = 4096
PUT_TOKEN = "a4e9c701d83b4f2695ac7e1d0b38f642"


def authorized_put(header):
    return hmac.compare_digest(header or "", "Bearer " + PUT_TOKEN)


def rewrite_hello_target(data, relay, target):
    """Translate only embedded destinations pointing at this relay listener.

    Soku HELLO is 0x01 followed by two 16-byte sockaddr_in values. Leaving
    these as the relay address makes the real host treat a forwarded HELLO as
    a hole-punch request instead of a connection request.
    """
    if len(data) != 37 or data[0] != 1:
        return data
    result = bytearray(data)
    relay_ip = socket.inet_aton(relay[0])
    target_ip = socket.inet_aton(target[0])
    for offset in (1, 17):
        if result[offset:offset + 2] != b"\x02\x00":
            continue
        if (result[offset + 2:offset + 4] == relay[1].to_bytes(2, "big") and
                result[offset + 4:offset + 8] == relay_ip):
            result[offset + 2:offset + 4] = target[1].to_bytes(2, "big")
            result[offset + 4:offset + 8] = target_ip
    return bytes(result)


class Hub:
    def __init__(self, bind, public_ip, http_port, control_port, first_port, last_port,
                 allow_private_targets=False):
        self.bind = bind
        self.public_ip = public_ip
        self.http_port = http_port
        self.control_port = control_port
        self.ports = range(first_port, last_port + 1)
        self.allow_private_targets = allow_private_targets
        self.selector = selectors.DefaultSelector()
        self.lock = threading.RLock()
        self.snapshots = {}
        self.games = {}
        self.hosts = {}
        self.last_put = {}
        self.control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.control.bind(("127.0.0.1", control_port))
        self.control.setblocking(False)
        self.selector.register(self.control, selectors.EVENT_READ, ("control", None))

    def close_game(self, key):
        game = self.games.pop(key, None)
        if not game:
            return
        for viewer in game["viewers"].values():
            self.selector.unregister(viewer["upstream"])
            viewer["upstream"].close()
        self.selector.unregister(game["listener"])
        game["listener"].close()

    def sync_games(self, now):
        wanted = {}
        for lobby, (instance, timestamp, entries) in list(self.snapshots.items()):
            if now - timestamp > SNAPSHOT_TTL:
                del self.snapshots[lobby]
                continue
            for entry in entries:
                try:
                    host = ipaddress.IPv4Address(entry["host"])
                    port = int(entry["port"])
                    if (not host.is_global and not self.allow_private_targets) or not 1 <= port <= 65535:
                        continue
                    key = (lobby, instance, int(entry["machine"]), int(entry["generation"]))
                    wanted[key] = (str(host), port, str(entry["host_name"])[:80], str(entry["client_name"])[:80])
                except (KeyError, ValueError, TypeError):
                    continue
        for key in list(self.games):
            if key not in wanted:
                self.close_game(key)
        used = {game["port"] for game in self.games.values()}
        for key, (host, port, host_name, client_name) in wanted.items():
            self.hosts.pop((host, port), None)
            if key in self.games:
                game = self.games[key]
                if game["target"] != (host, port):
                    for viewer in game["viewers"].values():
                        self.selector.unregister(viewer["upstream"])
                        viewer["upstream"].close()
                    game["viewers"].clear()
                game.update(target=(host, port), host_name=host_name, client_name=client_name)
                continue
            for relay_port in self.ports:
                if relay_port in used:
                    continue
                listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    listener.bind((self.bind, relay_port))
                except OSError:
                    listener.close()
                    continue
                listener.setblocking(False)
                game = dict(port=relay_port, listener=listener, target=(host, port),
                            host_name=host_name, client_name=client_name, viewers={})
                self.games[key] = game
                self.selector.register(listener, selectors.EVENT_READ, ("listener", key))
                used.add(relay_port)
                break

    def receive_control(self):
        data, address = self.control.recvfrom(65536)
        if address[0] != "127.0.0.1" or len(data) > 60000:
            return
        try:
            snapshot = json.loads(data)
            lobby = int(snapshot["lobby"])
            instance = int(snapshot["instance"])
            entries = snapshot["games"]
            if not 1 <= lobby <= 65535 or not isinstance(entries, list) or len(entries) > 256:
                return
        except (ValueError, KeyError, TypeError):
            return
        with self.lock:
            self.snapshots[lobby] = (instance, time.monotonic(), entries)
            self.sync_games(time.monotonic())

    def receive_viewer(self, key):
        game = self.games.get(key)
        if not game:
            return
        data, address = game["listener"].recvfrom(MAX_PACKET + 1)
        if len(data) > MAX_PACKET or not data:
            return
        now = time.monotonic()
        viewer = game["viewers"].get(address)
        if viewer is None:
            if len(game["viewers"]) >= MAX_VIEWERS or sum(
                len(item["viewers"]) for item in self.games.values()
            ) >= MAX_TOTAL_VIEWERS:
                return
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.setblocking(False)
            viewer = dict(upstream=upstream, last=now)
            game["viewers"][address] = viewer
            self.selector.register(upstream, selectors.EVENT_READ, ("upstream", key, address))
        viewer["last"] = now
        try:
            data = rewrite_hello_target(data, (self.public_ip, game["port"]), game["target"])
            viewer["upstream"].sendto(data, game["target"])
        except OSError:
            pass

    def receive_upstream(self, key, address):
        game = self.games.get(key)
        viewer = game and game["viewers"].get(address)
        if not viewer:
            return
        try:
            data, source = viewer["upstream"].recvfrom(MAX_PACKET + 1)
            # Some NAT/forwarding setups answer from another port on the same
            # host. Never accept a response from a different IP.
            if source[0] == game["target"][0] and 0 < len(data) <= MAX_PACKET:
                game["listener"].sendto(data, address)
                viewer["last"] = time.monotonic()
        except OSError:
            pass

    def cleanup(self, now):
        self.sync_games(now)
        for game in self.games.values():
            for address, viewer in list(game["viewers"].items()):
                if now - viewer["last"] > VIEWER_TTL:
                    self.selector.unregister(viewer["upstream"])
                    viewer["upstream"].close()
                    del game["viewers"][address]
        for key, entry in list(self.hosts.items()):
            if now - entry["last"] > HOST_TTL:
                del self.hosts[key]

    def list_games(self):
        with self.lock:
            result = []
            for game in self.games.values():
                result.append(dict(started=True, spectatable=True,
                                   host_name=game["host_name"], client_name=game["client_name"],
                                   host_character="", client_character="", host_country="",
                                   client_country="", ip="{}:{}".format(self.public_ip, game["port"])))
            for entry in self.hosts.values():
                result.append(dict(started=False, host_name=entry["name"],
                                   host_country="", message=entry["message"],
                                   autopunch=False, ranked=False,
                                   ip="{}:{}".format(entry["host"], entry["port"])))
            return result

    def add_host(self, data, source):
        try:
            host = ipaddress.IPv4Address(data["host"])
            port = int(data["port"])
            if not host.is_global or not 1 <= port <= 65535:
                return False
            name = str(data["profile_name"])[:80]
            message = str(data.get("message", ""))[:160]
        except (KeyError, ValueError, TypeError):
            return False
        now = time.monotonic()
        with self.lock:
            if now - self.last_put.get(source, 0) < 15:
                return False
            self.last_put[source] = now
            if len(self.hosts) >= 256 and (str(host), port) not in self.hosts:
                return False
            self.hosts[(str(host), port)] = dict(host=str(host), port=port, name=name,
                                                  message=message, last=now)
        return True

    def run(self):
        hub = self

        class Handler(BaseHTTPRequestHandler):
            def reply(self, status, value):
                body = json.dumps(value, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path != "/games":
                    self.reply(404, {})
                else:
                    self.reply(200, hub.list_games())

            def do_PUT(self):
                if self.path != "/games":
                    return self.reply(404, {})
                if not authorized_put(self.headers.get("Authorization")):
                    return self.reply(401, {"error": "Unauthorized"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 4096:
                        return self.reply(413, {})
                    data = json.loads(self.rfile.read(length))
                except (ValueError, TypeError):
                    return self.reply(400, {})
                self.reply(200 if hub.add_host(data, self.client_address[0]) else 400, {})

            def log_message(self, fmt, *args):
                print("HTTP {} {}".format(self.client_address[0], fmt % args), flush=True)

        http = ThreadingHTTPServer((self.bind, self.http_port), Handler)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        print("Hostlist HTTP :{}; control 127.0.0.1:{}; relay UDP {}-{}".format(
            self.http_port, self.control_port, self.ports.start, self.ports.stop - 1), flush=True)
        while True:
            for key, _ in self.selector.select(timeout=1):
                kind, *details = key.data
                with self.lock:
                    if kind == "control":
                        self.receive_control()
                    elif kind == "listener":
                        self.receive_viewer(details[0])
                    else:
                        self.receive_upstream(details[0], details[1])
            with self.lock:
                self.cleanup(time.monotonic())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--http-port", type=int, default=5500)
    parser.add_argument("--control-port", type=int, default=18081)
    parser.add_argument("--first-port", type=int, default=5501)
    parser.add_argument("--last-port", type=int, default=5599)
    args = parser.parse_args()
    Hub(args.bind, args.public_ip, args.http_port, args.control_port,
        args.first_port, args.last_port).run()


