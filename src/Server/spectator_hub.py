"""One shared hostlist and transparent spectator UDP relay for all lobby processes.

Lobby processes publish complete snapshots to loopback UDP/18081. The public
HTTP endpoint keeps the existing /games shape; each started game gets a public
UDP port. Game datagrams are passed through except for spectator-tree
HELLO/REDIRECT addresses used during hole punching.
"""

import argparse
import hmac
import ipaddress
import json
import os
import re
import selectors
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SNAPSHOT_TTL = 12
VIEWER_TTL = 90
HOST_TTL = 900
MAX_VIEWERS = 64
MAX_TOTAL_VIEWERS = 512
MAX_PACKET = 4096
MAX_ROUTES_PER_GAME = 8
HANDSHAKE_TIMEOUT = 5
IPV6_FALLBACK_DELAY = 2
HELLO_FALLBACK_DELAY = 0.75
MAX_MAP_HOPS = 3
IPV6MAP_ANNOUNCE = 0x36
IPV6MAP_ANNOUNCE_HOP = 0x05
HOST_GAME = 0x0D
GAME_MATCH = 0x04
GAME_REPLAY_REQUEST = 0x0B
CLIENT_GAME = 0x0E
INIT_REQUEST = 0x05
OLLEH = 0x03
REDIRECT = 0x08
INIT_SUCCESS = 0x06
QUIT = 0x0B
PROBE_COOLDOWN = 20
PROBE_FAST_ATTEMPTS = 3
PROBE_SLOW_COOLDOWN = 90
PROBE_WAIT = 3.0
COUNTRY_RETRY_DELAY = 5
COUNTRY_CACHE_LIMIT = 4096
REGION_LOG_TAIL = 8 * 1024 * 1024
REGION_LOG_POLL = 2
GEO_TOOL = "/root/ips/ips"
GEO_DATABASE = "/root/ips/qqwry_251208.dat"
# The lobby monitors already append "<name> <ip> [<region>] … has joined the
# lobby." to connect.log, which gives the region of both players without any
# lobby-server change.
CONNECT_LOG = "/root/connect.log"
IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
# The bundled qqwry database reports regions as "<国家>[–<省>…]", so the
# first dash separated chunk picks the flag key used by the client
# (assets/flags/list.json uses ISO 3166-1 alpha-2 keys).
COUNTRY_BY_REGION = {
    "中国": "cn", "日本": "jp", "韩国": "kr", "朝鲜": "kp", "蒙古": "mn",
    "美国": "us", "加拿大": "ca", "墨西哥": "mx", "巴西": "br", "阿根廷": "ar",
    "智利": "cl", "秘鲁": "pe", "哥伦比亚": "co", "委内瑞拉": "ve",
    "英国": "gb", "法国": "fr", "德国": "de", "意大利": "it", "西班牙": "es",
    "葡萄牙": "pt", "荷兰": "nl", "比利时": "be", "卢森堡": "lu", "瑞士": "ch",
    "奥地利": "at", "瑞典": "se", "挪威": "no", "丹麦": "dk", "芬兰": "fi",
    "冰岛": "is", "爱尔兰": "ie", "波兰": "pl", "捷克": "cz", "匈牙利": "hu",
    "罗马尼亚": "ro", "保加利亚": "bg", "希腊": "gr", "土耳其": "tr", "俄罗斯": "ru",
    "乌克兰": "ua", "白俄罗斯": "by", "塞尔维亚": "rs", "克罗地亚": "hr",
    "斯洛伐克": "sk", "斯洛文尼亚": "si", "立陶宛": "lt", "拉脱维亚": "lv",
    "爱沙尼亚": "ee", "摩尔多瓦": "md", "以色列": "il", "沙特阿拉伯": "sa",
    "阿联酋": "ae", "卡塔尔": "qa", "科威特": "kw", "伊朗": "ir", "伊拉克": "iq",
    "印度": "in", "巴基斯坦": "pk", "孟加拉国": "bd", "斯里兰卡": "lk", "尼泊尔": "np",
    "哈萨克斯坦": "kz", "乌兹别克斯坦": "uz", "吉尔吉斯斯坦": "kg",
    "塔吉克斯坦": "tj", "土库曼斯坦": "tm", "阿富汗": "af",
    "越南": "vn", "泰国": "th", "缅甸": "mm", "柬埔寨": "kh", "老挝": "la",
    "马来西亚": "my", "新加坡": "sg", "印度尼西亚": "id", "菲律宾": "ph", "文莱": "bn",
    "澳大利亚": "au", "新西兰": "nz", "南非": "za", "埃及": "eg", "尼日利亚": "ng",
    "肯尼亚": "ke", "摩洛哥": "ma", "突尼斯": "tn", "阿尔及利亚": "dz",
}
COUNTRY_BY_REGION_SPECIAL = (("香港", "hk"), ("台湾", "tw"), ("澳门", "mo"))
CHARACTER_NAMES = (
    "reimu", "marisa", "sakuya", "alice", "patchouli", "youmu", "remilia", "yuyuko", "yukari",
    "suika", "reisen", "aya", "komachi", "iku", "tenshi", "sanae", "cirno", "meiling",
    "utsuho", "suwako",
)
SPECTATE_GAME_IDS = (
    bytes.fromhex("6C7365D9FFC46E488D7CA19231347295"),
    bytes.fromhex("647365D9FFC46E488D7CA19231347295"),
    bytes.fromhex("6E7365D9FFC46E488D7CA19231347295"),
    bytes.fromhex("46C967C8ACF2444DB8B1ECDED4D5404A"),
)
INIT_REQUEST_STUFF = bytes([0x3B, 0xAA, 0x01, 0x6E, 0x28, 0x00, 0xFC, 0x30])
PUT_TOKEN = "a4e9c701d83b4f2695ac7e1d0b38f642"


def authorized_put(header):
    return hmac.compare_digest(header or "", "Bearer " + PUT_TOKEN)


def country_from_region(region):
    """Turn a qqwry region string ("中国–广东–深圳 移动") into a flag key ("cn")."""
    text = region.strip().strip("[]").strip()
    if not text:
        return ""
    for dash in ("—", "－", "－", "-", "–"):
        text = text.replace(dash, "–")
    parts = [part.strip() for part in text.split("–") if part.strip()]
    if not parts:
        return ""
    first = parts[0]
    tail = " ".join(parts[1:]) if len(parts) > 1 else text
    if first.startswith("中国"):
        rest = (first[2:].strip() + " " + tail).strip()
        for name, code in COUNTRY_BY_REGION_SPECIAL:
            if rest.startswith(name):
                return code
        return "cn"
    for name, code in COUNTRY_BY_REGION.items():
        if first.startswith(name):
            return code
    for name, code in COUNTRY_BY_REGION_SPECIAL:
        if first.startswith(name):
            return code
    return ""


def parse_geo_country(output):
    start = output.find("[")
    end = output.rfind("]")
    if start < 0 or end <= start:
        return ""
    return country_from_region(output[start + 1:end])


def parse_game_match(data):
    """Read the two characters out of a HOST_GAME/GAME_MATCH packet.

    The packet is 0x0D 0x04 followed by a packed PlayerMatchData for each
    player (character, skin, deck id, deck size, cards, disabled flag), then
    stage, music, seed and match id.
    """
    if len(data) < 12 or data[0] != HOST_GAME or data[1] != GAME_MATCH:
        return None
    body = data[2:]
    offset = 0
    characters = []
    for _ in range(2):
        if offset + 4 > len(body):
            return None
        character = body[offset]
        deck_size = body[offset + 3]
        offset += 4 + deck_size * 2
        if offset >= len(body):
            return None
        offset += 1
        characters.append(character)
    if any(character >= len(CHARACTER_NAMES) for character in characters):
        return None
    return CHARACTER_NAMES[characters[0]], CHARACTER_NAMES[characters[1]]


def build_spectate_hello(relay):
    return b"\x01" + sockaddr(relay) + sockaddr(relay) + b"\x00\x00\x00\xbc"


def build_init_request(game_id):
    base = bytes([INIT_REQUEST]) + game_id + INIT_REQUEST_STUFF + bytes([0])
    return base + bytes(65 - len(base))


def build_replay_request(frame_id, match_id=0):
    return bytes([CLIENT_GAME, GAME_REPLAY_REQUEST]) + struct.pack("<I", frame_id) + bytes([match_id])



def ipv6map_endpoint(data):
    """Parse an IPv6Map hand-off announcement.

    Hosts behind IPv6Map answer a spectator INIT_REQUEST with a 0x36/0x05
    packet carrying the IPv6 endpoint that actually serves the session
    ("6" + 0x05 + flags + 16-byte address + port).  Connecting to the
    snapshot address never completes the handshake, so the relay has to
    follow the announced endpoint instead of forwarding the packet.
    """
    if len(data) < 24 or data[0] != IPV6MAP_ANNOUNCE or data[1] != IPV6MAP_ANNOUNCE_HOP:
        return None
    try:
        address = str(ipaddress.IPv6Address(data[6:22]))
        port = int.from_bytes(data[22:24], "big")
    except (ValueError, TypeError):
        return None
    if not 1 <= port <= 65535:
        return None
    return address, port


def rewrite_hello_target(data, relay, target):
    """Translate only embedded destinations pointing at this relay listener.

    Soku HELLO is 0x01 followed by two 16-byte sockaddr_in values. Leaving
    these as the relay address makes the real host treat a forwarded HELLO as
    a hole-punch request instead of a connection request.
    """
    return rewrite_hello_routes(data, {relay: target})


def sockaddr(address):
    return b"\x02\x00" + address[1].to_bytes(2, "big") + socket.inet_aton(address[0]) + b"\x00" * 8


def parse_sockaddr(data):
    if len(data) != 16 or data[:2] != b"\x02\x00":
        return None
    return socket.inet_ntoa(data[4:8]), int.from_bytes(data[2:4], "big")


def rewrite_hello_routes(data, routes):
    if len(data) != 37 or data[0] != 1:
        return data
    result = bytearray(data)
    for offset in (1, 17):
        address = parse_sockaddr(result[offset:offset + 16])
        if address in routes:
            target = routes[address]
            result[offset + 2:offset + 4] = target[1].to_bytes(2, "big")
            result[offset + 4:offset + 8] = socket.inet_aton(target[0])
    return bytes(result)


def make_target(host, port):
    address = ipaddress.ip_address(host)
    if address.version == 4:
        return socket.AF_INET, str(address), port
    return socket.AF_INET6, str(address), port


def target_endpoint(target):
    return target[1], target[2]


def target_sockaddr(target):
    if target[0] == socket.AF_INET6:
        return target[1], target[2], 0, 0
    return target[1], target[2]


def source_endpoint(source):
    return source[0], source[1]


def open_upstream(target):
    upstream = socket.socket(target[0], socket.SOCK_DGRAM)
    upstream.setblocking(False)
    return upstream


class Hub:
    def __init__(self, bind, public_ip, http_port, control_port, first_port, last_port,
                 allow_private_targets=False, debug_viewer=None, debug_all=False,
                 geo_tool=GEO_TOOL, geo_database=GEO_DATABASE, connect_log=CONNECT_LOG):
        self.bind = bind
        self.public_ip = public_ip
        self.http_port = http_port
        self.control_port = control_port
        self.ports = range(first_port, last_port + 1)
        self.allow_private_targets = allow_private_targets
        self.debug_viewer = debug_viewer
        self.debug_all = debug_all
        self.geo_tool = geo_tool
        self.geo_database = geo_database
        self.geo_enabled = bool(geo_tool) and os.path.exists(geo_tool)
        self.connect_log = connect_log if (connect_log and os.path.exists(connect_log)) else ""
        self.countries = {}
        self.player_countries = {}
        self.player_ips = {}
        self.region_pending = ""
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

    def resolve_country(self, address):
        """Look the address up in the bundled region database (cached)."""
        if not address:
            return ""
        with self.lock:
            if address in self.countries:
                return self.countries[address]
        code = ""
        if self.geo_enabled:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                ip = None
            if ip is not None and ip.version == 4 and ip.is_global:
                try:
                    result = subprocess.run(
                        [self.geo_tool, "--file", self.geo_database, address],
                        timeout=4, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    code = parse_geo_country(result.stdout.decode("utf-8", "replace"))
                except (OSError, subprocess.SubprocessError):
                    code = ""
        with self.lock:
            if len(self.countries) >= COUNTRY_CACHE_LIMIT:
                self.countries.clear()
            self.countries[address] = code
        return code

    def consume_region_line(self, line):
        """Record name -> ip/country from one connect.log join line."""
        if " has joined the lobby." not in line:
            return
        body = line.split(",", 1)[1] if "," in line else line
        matches = list(IP_REGEX.finditer(body))
        if not matches:
            return
        name = body[:matches[0].start()].strip()
        if not name:
            # Relayed connections are named after their relay address
            # ("8.134.214.80_45388 223.73.177.125 (…) has joined the lobby."),
            # so the first token is the name even though it starts with an IP.
            name = body.split(" ", 1)[0].strip()
        if not name:
            return
        # The last address is the player's own one; the first can be a relay.
        address = matches[-1].group()
        tail = body[matches[-1].end():]
        country = ""
        start = tail.find("[")
        end = tail.find("]")
        if 0 <= start < end:
            country = country_from_region(tail[start + 1:end])
        with self.lock:
            self.player_ips[name] = address
            if country:
                self.player_countries[name] = country

    def consume_region_chunk(self, chunk):
        text = self.region_pending + chunk
        lines = text.split("\n")
        self.region_pending = lines.pop()
        for line in lines:
            self.consume_region_line(line)

    def region_log_loop(self):
        if not self.connect_log:
            return
        try:
            offset = max(0, os.path.getsize(self.connect_log) - REGION_LOG_TAIL)
        except OSError:
            return
        while True:
            time.sleep(REGION_LOG_POLL)
            try:
                size = os.path.getsize(self.connect_log)
                if size < offset:
                    # Log rotated or truncated: start over.
                    offset = 0
                    self.region_pending = ""
                    with self.lock:
                        self.player_countries.clear()
                        self.player_ips.clear()
                if size <= offset:
                    continue
                with open(self.connect_log, "r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(offset)
                    chunk = handle.read(4 << 20)
                    offset = handle.tell()
                self.consume_region_chunk(chunk)
            except OSError:
                continue

    def country_loop(self):
        while True:
            time.sleep(COUNTRY_RETRY_DELAY)
            pending = []
            with self.lock:
                for key, game in self.games.items():
                    # The lobby logs carry the players' own addresses, so their
                    # regions are more accurate than the advertised game
                    # address (which is often an IPv6Map/swarm relay).
                    host_code = self.player_countries.get(game.get("host_name", ""), "")
                    client_code = self.player_countries.get(game.get("client_name", ""), "")
                    if host_code and game.get("host_country") != host_code:
                        game["host_country"] = host_code
                    if client_code and game.get("client_country") != client_code:
                        game["client_country"] = client_code
                    if self.geo_enabled:
                        if not game.get("host_country") and game.get("host_ip"):
                            pending.append((key, "host_country", game["host_ip"]))
                        if not game.get("client_country") and game.get("client_ip"):
                            pending.append((key, "client_country", game["client_ip"]))
            for key, field, address in pending:
                code = self.resolve_country(address)
                if code:
                    with self.lock:
                        game = self.games.get(key)
                        if game and not game.get(field):
                            game[field] = code


    def close_game(self, key):
        game = self.games.pop(key, None)
        if not game:
            return
        for viewer in game["viewers"].values():
            self.close_viewer(viewer)
        for route in game["routes"].values():
            self.selector.unregister(route["listener"])
            route["listener"].close()

    def close_viewer(self, viewer):
        for upstream in viewer["upstreams"].values():
            self.selector.unregister(upstream)
            upstream.close()

    def upstream_for(self, key, address, viewer, target):
        family = target[0]
        upstream = viewer["upstreams"].get(family)
        if upstream is None:
            upstream = open_upstream(target)
            viewer["upstreams"][family] = upstream
            self.selector.register(upstream, selectors.EVENT_READ,
                                   ("upstream", key, address, family))
        return upstream

    def switch_ipv6map_target(self, key, address, viewer, route, endpoint):
        """Re-point one viewer's route at an announced IPv6Map endpoint."""
        target = make_target(endpoint[0], endpoint[1])
        current = viewer["actual_targets"].get(route["port"], route["target"])
        if target_endpoint(current) == target_endpoint(target):
            return False
        if viewer["map_hops"] >= MAX_MAP_HOPS:
            return False
        packet = viewer["last_init"] or viewer["last_hello"]
        if not packet:
            return False
        viewer["map_hops"] += 1
        viewer["map_switched"] = True
        viewer["actual_targets"][route["port"]] = target
        try:
            upstream = self.upstream_for(key, address, viewer, target)
            for replay in (viewer["last_hello"], viewer["last_init"]):
                if replay:
                    upstream.sendto(replay, target_sockaddr(target))
        except OSError:
            return False
        return True

    def close_child_routes(self, game):
        for port, route in list(game["routes"].items()):
            if port == game["port"]:
                continue
            self.selector.unregister(route["listener"])
            route["listener"].close()
            del game["routes"][port]

    def add_route(self, key, target):
        game = self.games[key]
        for route in game["routes"].values():
            if route["target"] == target:
                return route
        if len(game["routes"]) >= MAX_ROUTES_PER_GAME:
            return None
        used = {route["port"] for item in self.games.values() for route in item["routes"].values()}
        for port in self.ports:
            if port in used:
                continue
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                listener.bind((self.bind, port))
            except OSError:
                listener.close()
                continue
            listener.setblocking(False)
            route = dict(port=port, listener=listener, target=target, last=time.monotonic())
            game["routes"][port] = route
            self.selector.register(listener, selectors.EVENT_READ, ("listener", key, port))
            return route
        return None

    def sync_games(self, now):
        wanted = {}
        for lobby, (instance, timestamp, entries) in list(self.snapshots.items()):
            if now - timestamp > SNAPSHOT_TTL:
                del self.snapshots[lobby]
                continue
            for entry in entries:
                try:
                    fallback = None
                    try:
                        ipv4 = ipaddress.IPv4Address(entry["host"])
                        port = int(entry["port"])
                        if (ipv4.is_global or self.allow_private_targets) and 1 <= port <= 65535:
                            fallback = make_target(str(ipv4), port)
                    except (KeyError, ValueError, TypeError):
                        pass
                    # The Soku spectator HELLO packet embeds two sockaddr_in
                    # structures.  They cannot describe an IPv6 endpoint, so
                    # use the reported IPv4 endpoint whenever it exists.
                    # A pure IPv6 game can still be attempted below, but must
                    # not displace a usable IPv4 route.
                    target = fallback
                    if entry.get("ipv6") and entry.get("port6"):
                        ipv6 = ipaddress.IPv6Address(entry["ipv6"])
                        port6 = int(entry["port6"])
                        if (target is None and
                                (ipv6.is_global or self.allow_private_targets) and 1 <= port6 <= 65535):
                            target = make_target(str(ipv6), port6)
                    if target is None:
                        continue
                    key = (lobby, instance, int(entry["machine"]), int(entry["generation"]))
                    # host_ip/client_ip are the players' lobby connection
                    # addresses, which is what the region database knows; the
                    # advertised "host" address is only a fallback because it
                    # can be a relay (IPv6Map/swarm).
                    wanted[key] = (target, fallback if target != fallback else None,
                                   str(entry["host_name"])[:80], str(entry["client_name"])[:80],
                                   str(entry.get("host_ip") or entry.get("host") or ""),
                                   str(entry.get("client_ip") or ""))
                except (KeyError, ValueError, TypeError):
                    continue
        for key in list(self.games):
            if key not in wanted:
                self.close_game(key)
        used = {route["port"] for game in self.games.values() for route in game["routes"].values()}
        for key, (target, fallback, host_name, client_name, host_ip, client_ip) in wanted.items():
            self.hosts.pop(target_endpoint(target), None)
            if key in self.games:
                game = self.games[key]
                if game["target"] != target:
                    for viewer in game["viewers"].values():
                        self.close_viewer(viewer)
                    game["viewers"].clear()
                    self.close_child_routes(game)
                game.update(target=target, fallback=fallback,
                            host_name=host_name, client_name=client_name,
                            host_ip=host_ip, client_ip=client_ip)
                game["routes"][game["port"]]["target"] = target
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
                root_route = dict(port=relay_port, listener=listener, target=target,
                                  last=time.monotonic())
                game = dict(port=relay_port, listener=listener, target=target, fallback=fallback,
                            host_name=host_name, client_name=client_name, viewers={},
                            spectatable=True, host_character="", client_character="",
                            host_country="", client_country="",
                            host_ip=host_ip, client_ip=client_ip,
                            probe_attempts=0, probe_last=0.0, probe_done=False,
                            routes={relay_port: root_route})
                self.games[key] = game
                self.selector.register(listener, selectors.EVENT_READ, ("listener", key, relay_port))
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

    def receive_viewer(self, key, route_port=None):
        game = self.games.get(key)
        if not game:
            return
        route_port = game["port"] if route_port is None else route_port
        route = game["routes"].get(route_port)
        if not route:
            return
        data, address = route["listener"].recvfrom(MAX_PACKET + 1)
        if len(data) > MAX_PACKET or not data:
            return
        now = time.monotonic()
        viewer = game["viewers"].get(address)
        if viewer is None:
            if len(game["viewers"]) >= MAX_VIEWERS or sum(
                len(item["viewers"]) for item in self.games.values()
            ) >= MAX_TOTAL_VIEWERS:
                return
            viewer = dict(upstreams={}, last=now, actual_targets={},
                          pending_route=None, last_sent_route=route_port,
                          handshake_started=None, spectator_ready=False,
                          last_init=None, first_hello=None, last_hello=None,
                          root_hello_response=False, fallback_used=False,
                          root_progress=False, map_hops=0, map_switched=False)
            game["viewers"][address] = viewer
        viewer["last"] = now
        viewer["last_sent_route"] = route_port
        route["last"] = now
        if route_port == game["port"] and data[0] == 1 and len(data) == 37:
            if viewer["first_hello"] is None:
                viewer["first_hello"] = now
            viewer["last_hello"] = data
        if data[0] == 5 and len(data) >= 65:
            if viewer["handshake_started"] is None:
                viewer["handshake_started"] = now
            if route_port == game["port"]:
                viewer["last_init"] = data
        try:
            routes = {
                (self.public_ip, port): target_endpoint(viewer["actual_targets"].get(port, item["target"]))
                for port, item in game["routes"].items()
                if viewer["actual_targets"].get(port, item["target"])[0] == socket.AF_INET
            }
            data = rewrite_hello_routes(data, routes)
            target = viewer["actual_targets"].get(route_port, route["target"])
            upstream = self.upstream_for(key, address, viewer, target)
            sent = upstream.sendto(data, target_sockaddr(target))
            if self.debug_viewer == address[0] and data[0] != 1:
                source = upstream.getsockname()
                print("DEBUG viewer {}:{} route {} -> {}:{} from {}:{} opcode {} length {} sent {}".format(
                    address[0], address[1], route_port, target[1], target[2],
                    source[0], source[1], data[0], len(data), sent), flush=True)
        except OSError as error:
            if self.debug_viewer == address[0]:
                print("DEBUG viewer send error {}:{} {}".format(
                    address[0], address[1], error), flush=True)

    @staticmethod
    def route_for_source(game, viewer, source, opcode):
        # Prefer the exact endpoint learned from the child's punch response.
        for port, route in game["routes"].items():
            if target_endpoint(viewer["actual_targets"].get(port, route["target"])) == source_endpoint(source):
                return route
        pending = game["routes"].get(viewer["pending_route"])
        if opcode == 3 and pending and source[0] == pending["target"][1]:
            return pending
        matching = [route for port, route in game["routes"].items()
                    if (route["target"][1] == source[0] or
                        viewer["actual_targets"].get(port, route["target"])[1] == source[0])]
        if len(matching) == 1:
            return matching[0]
        return game["routes"].get(viewer["last_sent_route"]) if any(
            route["port"] == viewer["last_sent_route"] for route in matching) else None

    def receive_upstream(self, key, address, family=None):
        game = self.games.get(key)
        viewer = game and game["viewers"].get(address)
        if not viewer:
            return
        try:
            if family is None:
                family = game["target"][0]
            data, source = viewer["upstreams"][family].recvfrom(MAX_PACKET + 1)
            if not 0 < len(data) <= MAX_PACKET:
                return
            route = self.route_for_source(game, viewer, source, data[0])
            if self.debug_viewer == address[0]:
                print("DEBUG upstream {}:{} opcode {} length {} route {}".format(
                    source[0], source[1], data[0], len(data),
                    route["port"] if route else "dropped"), flush=True)
            if not route:
                return
            endpoint = ipv6map_endpoint(data)
            if endpoint and self.switch_ipv6map_target(key, address, viewer, route, endpoint):
                # The IPv6Map announcement is consumed by the relay: the
                # session continues against the announced endpoint, so the
                # viewer keeps talking to this relay port as usual.
                viewer["last"] = time.monotonic()
                return
            if (viewer["fallback_used"] and not viewer["map_switched"] and
                    route["port"] == game["port"] and family == socket.AF_INET6):
                return
            if route["port"] == game["port"]:
                viewer["root_hello_response"] = True
            if route["port"] == game["port"] and data[0] in (6, 8):
                viewer["root_progress"] = True
            if data[0] == HOST_GAME and len(data) > 3 and data[1] == GAME_MATCH:
                # A spectator session already carries the match setup, so the
                # hostlist characters can be filled without any extra probe.
                characters = parse_game_match(data)
                if characters:
                    game["host_character"], game["client_character"] = characters
                    game["probe_done"] = True
            if data[0] == 8 and len(data) == 69:
                target = parse_sockaddr(data[5:21])
                if target:
                    host = ipaddress.IPv4Address(target[0])
                    if (host.is_global or self.allow_private_targets) and target[1]:
                        child = self.add_route(key, make_target(*target))
                        if child:
                            viewer["pending_route"] = child["port"]
                            rewritten = bytearray(data)
                            rewritten[7:9] = child["port"].to_bytes(2, "big")
                            rewritten[9:13] = socket.inet_aton(self.public_ip)
                            data = bytes(rewritten)
            elif data[0] == 3 and viewer["pending_route"] == route["port"]:
                # A punch can make the child answer from a different UDP port
                # than the one carried in REDIRECT. Keep this endpoint for the
                # rest of this viewer's session.
                viewer["actual_targets"][route["port"]] = make_target(*source_endpoint(source))
                viewer["pending_route"] = None
            elif data[0] == 6 and viewer["handshake_started"] is not None:
                viewer["spectator_ready"] = True
            route["listener"].sendto(data, address)
            viewer["last"] = route["last"] = time.monotonic()
        except OSError:
            pass

    def cleanup(self, now):
        self.sync_games(now)
        for key, game in self.games.items():
            for address, viewer in list(game["viewers"].items()):
                hello_timed_out = (viewer["first_hello"] is not None and
                                   not viewer["root_hello_response"] and
                                   now - viewer["first_hello"] >= HELLO_FALLBACK_DELAY)
                init_timed_out = (viewer["last_init"] is not None and
                                  not viewer["root_progress"] and
                                  viewer["handshake_started"] is not None and
                                  now - viewer["handshake_started"] >= IPV6_FALLBACK_DELAY)
                if game["fallback"] and not viewer["fallback_used"] and (hello_timed_out or init_timed_out):
                    target = game["fallback"]
                    viewer["fallback_used"] = True
                    viewer["actual_targets"][game["port"]] = target
                    try:
                        packet = viewer["last_hello"] if hello_timed_out else viewer["last_init"]
                        if hello_timed_out:
                            packet = rewrite_hello_routes(packet, {
                                (self.public_ip, game["port"]): target_endpoint(target)
                            })
                        self.upstream_for(key, address, viewer, target).sendto(
                            packet, target_sockaddr(target))
                    except OSError:
                        pass
                if now - viewer["last"] > VIEWER_TTL:
                    self.close_viewer(viewer)
                    del game["viewers"][address]
            referenced = {viewer["last_sent_route"] for viewer in game["viewers"].values()}
            referenced.update(viewer["pending_route"] for viewer in game["viewers"].values())
            referenced.update(port for viewer in game["viewers"].values()
                              for port in viewer["actual_targets"])
            for port, route in list(game["routes"].items()):
                if port != game["port"] and port not in referenced and now - route["last"] > VIEWER_TTL:
                    self.selector.unregister(route["listener"])
                    route["listener"].close()
                    del game["routes"][port]
        for key, entry in list(self.hosts.items()):
            if now - entry["last"] > HOST_TTL:
                del self.hosts[key]

    def probe_characters(self, relay_port):
        """Open a throwaway spectator session and read only the match setup.

        The host pushes HOST_GAME/GAME_MATCH (which carries both characters)
        as soon as a spectator finishes the handshake, so the probe can quit
        right after parsing it instead of watching the match.
        """
        hello = build_spectate_hello((self.public_ip, relay_port))
        init = build_init_request(SPECTATE_GAME_IDS[0])
        target = ("127.0.0.1", relay_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        state = "hello"
        last_hello = 0.0
        last_send = 0.0
        frame = 0
        characters = None
        deadline = time.monotonic() + PROBE_WAIT + 4
        try:
            while characters is None and time.monotonic() < deadline:
                now = time.monotonic()
                if state == "hello" and now - last_hello >= 0.3:
                    sock.sendto(hello, target)
                    last_hello = now
                elif state == "init" and now - last_send >= 0.5:
                    sock.sendto(init, target)
                    last_send = now
                elif state == "watch" and now - last_send >= 0.05:
                    sock.sendto(build_replay_request(frame), target)
                    frame = (frame + 2) & 0xFFFF
                    last_send = now
                try:
                    data, _ = sock.recvfrom(MAX_PACKET + 1)
                except socket.timeout:
                    continue
                if not data:
                    continue
                if state == "hello" and data[0] == OLLEH:
                    state = "init"
                    last_send = 0.0
                elif data[0] == REDIRECT and len(data) == 69:
                    # The relay rewrote the child address to its own port.
                    target = ("127.0.0.1", int.from_bytes(data[7:9], "big"))
                    state = "hello"
                    last_hello = 0.0
                elif data[0] == INIT_SUCCESS:
                    state = "watch"
                    last_send = 0.0
                elif data[0] == HOST_GAME and len(data) > 3 and data[1] == GAME_MATCH:
                    characters = parse_game_match(data)
        except OSError:
            pass
        finally:
            try:
                sock.sendto(bytes([QUIT]), target)
            except OSError:
                pass
            sock.close()
        return characters

    def probe_candidates(self, now):
        """Games that still need a character probe, and when to try again.

        Hosts only publish HOST_GAME/GAME_MATCH once the match itself starts,
        so a game that appears while the players are still in the character
        select screen cannot be read yet: retry quickly at first and then keep
        retrying slowly until the match reports its setup.
        """
        candidates = []
        with self.lock:
            for key, game in self.games.items():
                if game.get("host_character") and game.get("client_character"):
                    continue
                if game.get("probe_done"):
                    continue
                attempts = game.get("probe_attempts", 0)
                cooldown = PROBE_COOLDOWN if attempts < PROBE_FAST_ATTEMPTS else PROBE_SLOW_COOLDOWN
                if now - game.get("probe_last", 0.0) < cooldown:
                    continue
                game["probe_attempts"] = attempts + 1
                game["probe_last"] = now
                candidates.append((key, game["port"]))
        return candidates

    def probe_loop(self):
        while True:
            time.sleep(1.0)
            for key, relay_port in self.probe_candidates(time.monotonic()):
                characters = self.probe_characters(relay_port)
                if characters:
                    with self.lock:
                        game = self.games.get(key)
                        if game:
                            game["host_character"], game["client_character"] = characters
                            game["probe_done"] = True
                time.sleep(0.2)

    def list_games(self):
        with self.lock:
            result = []
            for game in self.games.values():
                if not game["spectatable"]:
                    continue
                result.append(dict(started=True, spectatable=True,
                                   host_name=game["host_name"], client_name=game["client_name"],
                                   host_character=game.get("host_character", ""),
                                   client_character=game.get("client_character", ""),
                                   host_country=game.get("host_country", ""),
                                   client_country=game.get("client_country", ""),
                                   ip="{}:{}".format(self.public_ip, game["port"])))
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
        threading.Thread(target=self.probe_loop, daemon=True).start()
        threading.Thread(target=self.country_loop, daemon=True).start()
        if self.connect_log:
            threading.Thread(target=self.region_log_loop, daemon=True).start()
        print("Hostlist HTTP :{}; control 127.0.0.1:{}; relay UDP {}-{}; region db {}; lobby log {}".format(
            self.http_port, self.control_port, self.ports.start, self.ports.stop - 1,
            self.geo_database if self.geo_enabled else "disabled",
            self.connect_log or "disabled"), flush=True)
        while True:
            for key, _ in self.selector.select(timeout=1):
                kind, *details = key.data
                with self.lock:
                    if kind == "control":
                        self.receive_control()
                    elif kind == "listener":
                        self.receive_viewer(details[0], details[1])
                    else:
                        self.receive_upstream(details[0], details[1], details[2])
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
    parser.add_argument("--debug-viewer")
    parser.add_argument("--debug-all", action="store_true")
    parser.add_argument("--geo-tool", default=GEO_TOOL)
    parser.add_argument("--geo-database", default=GEO_DATABASE)
    parser.add_argument("--connect-log", default=CONNECT_LOG)
    args = parser.parse_args()
    Hub(args.bind, args.public_ip, args.http_port, args.control_port,
        args.first_port, args.last_port, debug_viewer=args.debug_viewer,
        debug_all=args.debug_all, geo_tool=args.geo_tool,
        geo_database=args.geo_database, connect_log=args.connect_log).run()
