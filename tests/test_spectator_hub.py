import importlib.util
import json
import socket
import time
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "src" / "Server" / "spectator_hub.py"
SPEC = importlib.util.spec_from_file_location("spectator_hub", MODULE)
hub_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hub_module)


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_udp_range(count):
    for _ in range(100):
        first = free_udp_port()
        if first + count > 65535:
            continue
        sockets = []
        try:
            for port in range(first, first + count):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                sock.bind(("127.0.0.1", port))
            return first
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("No free consecutive UDP ports")


class SpectatorHubTest(unittest.TestCase):
    def test_put_requires_bearer_token(self):
        self.assertFalse(hub_module.authorized_put(None))
        self.assertFalse(hub_module.authorized_put("Bearer wrong"))
        self.assertTrue(hub_module.authorized_put("Bearer " + hub_module.PUT_TOKEN))

    def setUp(self):
        self.control_port = free_udp_port()
        self.relay_port = free_udp_port()
        self.hub = hub_module.Hub("127.0.0.1", "43.136.23.115", 0,
                                  self.control_port, self.relay_port, self.relay_port,
                                  allow_private_targets=True)

    def tearDown(self):
        for key in list(self.hub.games):
            self.hub.close_game(key)
        self.hub.selector.unregister(self.hub.control)
        self.hub.control.close()
        self.hub.selector.close()

    def publish(self, lobby, instance, games):
        payload = json.dumps(dict(lobby=lobby, instance=instance, games=games)).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, ("127.0.0.1", self.control_port))
        self.hub.receive_control()

    def test_snapshots_share_list_and_remove_stale_matches(self):
        game = dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                    host_name="甲", client_name="乙")
        self.publish(6002, 100, [game])
        self.publish(6005, 200, [dict(game, machine=2)])
        # One configured relay port means the second lobby remains queued.
        self.assertEqual(1, len(self.hub.games))
        self.assertEqual("甲", self.hub.list_games()[0]["host_name"])
        self.publish(6002, 100, [])
        self.assertEqual(1, len(self.hub.games))
        self.assertEqual(6005, next(iter(self.hub.games))[0])

    def test_match_generation_replaces_old_relay(self):
        game = dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                    host_name="Host", client_name="Guest")
        self.publish(6002, 100, [game])
        self.publish(6002, 100, [dict(game, generation=2)])
        self.assertEqual(2, next(iter(self.hub.games))[3])

    def test_hostlist_put_is_rate_limited(self):
        entry = dict(host="8.8.8.8", port=10800, profile_name="Host", message="Ready")
        self.assertTrue(self.hub.add_host(entry, "1.2.3.4"))
        self.assertFalse(self.hub.add_host(entry, "1.2.3.4"))
        self.assertEqual("Ready", self.hub.list_games()[0]["message"])

    def test_hello_embedded_relay_address_is_translated(self):
        relay = ("43.136.23.115", 20000)
        target = ("124.223.180.38", 51011)
        extra = bytes.fromhex("000040c00000a0c0")
        sockaddr = b"\x02\x00" + relay[1].to_bytes(2, "big") + \
            socket.inet_aton(relay[0]) + extra
        hello = b"\x01" + sockaddr + sockaddr + b"\x00\x00\x00\xbc"
        converted = hub_module.rewrite_hello_target(hello, relay, target)
        expected = b"\x02\x00" + target[1].to_bytes(2, "big") + \
            socket.inet_aton(target[0]) + extra
        self.assertEqual(b"\x01" + expected + expected + hello[-4:], converted)
        self.assertEqual(hello, hub_module.rewrite_hello_target(hello, ("1.2.3.4", 20000), target))

    def test_unverified_match_is_not_listed(self):
        game = dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                    host_name="Host", client_name="Guest")
        self.publish(6002, 100, [game])
        key = next(iter(self.hub.games))
        self.hub.games[key]["spectatable"] = False
        self.assertEqual([], self.hub.list_games())

    def test_ipv6_snapshot_uses_ipv6_only_without_ipv4(self):
        game = dict(machine=1, generation=1, host="not-an-ip", port=10800,
                    ipv6="2606:4700:4700::1111", port6=10801,
                    host_name="Host", client_name="Guest")
        self.publish(6002, 100, [game])
        target = next(iter(self.hub.games.values()))["target"]
        self.assertEqual(socket.AF_INET6, target[0])
        self.assertEqual("2606:4700:4700::1111", target[1])
        self.assertEqual(10801, target[2])
        self.assertEqual(("2606:4700:4700::1111", 10801, 0, 0), hub_module.target_sockaddr(target))

    def test_ipv6_root_can_redirect_to_ipv4_child(self):
        try:
            root = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            root.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with root, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as child, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            child.bind(("127.0.0.1", 0))
            viewer.bind(("127.0.0.1", 0))
            root.settimeout(1)
            child.settimeout(1)
            viewer.settimeout(1)
            self.relay_port = free_udp_range(3)
            self.hub.ports = range(self.relay_port, self.relay_port + 3)
            self.publish(6002, 100, [dict(machine=1, generation=1,
                host="not-an-ip", port=11111, ipv6="::1", port6=root.getsockname()[1],
                host_name="Host", client_name="Guest")])
            key = next(iter(self.hub.games))
            self.assertEqual(socket.AF_INET6, self.hub.games[key]["target"][0])
            viewer.sendto(b"\x05" + bytes(64), ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            _, upstream_address = root.recvfrom(100)
            redirect = b"\x08" + (1).to_bytes(4, "little") + \
                hub_module.sockaddr(child.getsockname()) + bytes(48)
            root.sendto(redirect, upstream_address)
            self.hub.receive_upstream(key, viewer.getsockname(), socket.AF_INET6)
            rewritten, _ = viewer.recvfrom(100)
            child_port = hub_module.parse_sockaddr(rewritten[5:21])[1]
            viewer.sendto(b"\x05child", ("127.0.0.1", child_port))
            self.hub.receive_viewer(key, child_port)
            payload, child_upstream = child.recvfrom(100)
            self.assertEqual(b"\x05child", payload)
            child.sendto(b"\x06accepted", child_upstream)
            self.hub.receive_upstream(key, viewer.getsockname(), socket.AF_INET)
            self.assertEqual(b"\x06accepted", viewer.recvfrom(100)[0])

    def test_ipv4_is_preferred_when_both_endpoints_are_available(self):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as root, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            try:
                root.bind(("::1", 0))
            except OSError:
                self.skipTest("IPv6 loopback unavailable")
            fallback.bind(("127.0.0.1", 0))
            viewer.bind(("127.0.0.1", 0))
            fallback.settimeout(1)
            self.publish(6002, 100, [dict(machine=1, generation=1,
                host="127.0.0.1", port=fallback.getsockname()[1],
                ipv6="::1", port6=root.getsockname()[1],
                host_name="Host", client_name="Guest")])
            key = next(iter(self.hub.games))
            request = b"\x05" + bytes(64)
            viewer.sendto(request, ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            self.assertEqual(request, fallback.recvfrom(100)[0])

    def test_ipv4_hello_is_sent_without_waiting_for_ipv6(self):
        try:
            root = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            root.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with root, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            fallback.bind(("127.0.0.1", 0))
            viewer.bind(("127.0.0.1", 0))
            fallback.settimeout(1)
            self.publish(6002, 100, [dict(machine=1, generation=1,
                host="127.0.0.1", port=fallback.getsockname()[1],
                ipv6="::1", port6=root.getsockname()[1],
                host_name="Host", client_name="Guest")])
            key = next(iter(self.hub.games))
            relay = ("43.136.23.115", self.relay_port)
            hello = b"\x01" + hub_module.sockaddr(relay) * 2 + bytes.fromhex("000000bc")
            viewer.sendto(hello, ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            packet, upstream = fallback.recvfrom(100)
            self.assertEqual(fallback.getsockname(), hub_module.parse_sockaddr(packet[1:17]))
            self.assertEqual(fallback.getsockname(), hub_module.parse_sockaddr(packet[17:33]))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reply:
                reply.bind(("127.0.0.1", 0))
                reply.sendto(b"\x03", upstream)
            self.hub.receive_upstream(key, viewer.getsockname(), socket.AF_INET)
            viewer.settimeout(1)
            self.assertEqual(b"\x03", viewer.recvfrom(100)[0])

    def test_ipv6map_announcement_moves_the_session_to_the_named_endpoint(self):
        try:
            announced = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            announced.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with announced, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as base, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            base.bind(("127.0.0.1", 0))
            viewer.bind(("127.0.0.1", 0))
            base.settimeout(1)
            announced.settimeout(1)
            viewer.settimeout(1)
            self.publish(6002, 100, [dict(machine=1, generation=1,
                host="127.0.0.1", port=base.getsockname()[1],
                host_name="Host", client_name="Guest")])
            key = next(iter(self.hub.games))
            hello = b"\x01" + hub_module.sockaddr(("43.136.23.115", self.relay_port)) * 2 + \
                bytes.fromhex("000000bc")
            viewer.sendto(hello, ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            base.recvfrom(100)
            request = b"\x05" + bytes(64)
            viewer.sendto(request, ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            _, upstream = base.recvfrom(100)
            announcement = bytes([hub_module.IPV6MAP_ANNOUNCE, hub_module.IPV6MAP_ANNOUNCE_HOP]) + \
                bytes(4) + socket.inet_pton(socket.AF_INET6, "::1") + \
                announced.getsockname()[1].to_bytes(2, "big") + bytes(48)
            base.sendto(announcement, upstream)
            self.hub.receive_upstream(key, viewer.getsockname(), socket.AF_INET)
            # The announcement is consumed by the relay and the handshake is
            # replayed against the announced endpoint.
            payload, announced_upstream = announced.recvfrom(200)
            self.assertEqual(hello, payload)
            self.assertEqual(request, announced.recvfrom(200)[0])
            announced.sendto(b"\x06accepted", announced_upstream)
            self.hub.receive_upstream(key, viewer.getsockname(), socket.AF_INET6)
            self.assertEqual(b"\x06accepted", viewer.recvfrom(100)[0])
            # Subsequent viewer traffic follows the switched endpoint as well.
            viewer.sendto(b"\x0e\x0bpayload", ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            self.assertEqual(b"\x0e\x0bpayload", announced.recvfrom(100)[0])

    def test_ipv6map_announcement_is_ignored_after_the_hop_limit(self):
        game = dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                    host_name="Host", client_name="Guest")
        self.publish(6002, 100, [game])
        key = next(iter(self.hub.games))
        announcement = bytes([hub_module.IPV6MAP_ANNOUNCE, hub_module.IPV6MAP_ANNOUNCE_HOP]) + \
            bytes(4) + socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111") + \
            (10801).to_bytes(2, "big") + bytes(48)
        self.assertEqual(("2606:4700:4700::1111", 10801), hub_module.ipv6map_endpoint(announcement))
        self.assertIsNone(hub_module.ipv6map_endpoint(announcement[:20]))
        self.assertIsNone(hub_module.ipv6map_endpoint(b"\x01" + announcement[1:]))
        self.assertIsNone(hub_module.ipv6map_endpoint(b"\x36\x04" + bytes(40)))

    def test_game_match_characters_are_parsed(self):
        def player(character, skin, deck_id, deck_size):
            return bytes([character, skin, deck_id, deck_size]) + bytes(deck_size * 2) + b"\x00"

        packet = bytes([hub_module.HOST_GAME, hub_module.GAME_MATCH]) + \
            player(9, 2, 23, 20) + player(5, 1, 30, 20) + bytes([17, 16, 1, 2, 3, 4, 48])
        self.assertEqual(("suika", "youmu"), hub_module.parse_game_match(packet))
        self.assertIsNone(hub_module.parse_game_match(packet[:8]))
        self.assertIsNone(hub_module.parse_game_match(b"\x0d\x09" + packet[2:]))
        self.assertIsNone(hub_module.parse_game_match(bytes([hub_module.HOST_GAME, hub_module.GAME_MATCH]) +
                                                      player(200, 0, 1, 0) + player(0, 0, 1, 0) + bytes(7)))

    def test_spectate_packets_match_the_client_format(self):
        relay = ("43.136.23.115", 5501)
        hello = hub_module.build_spectate_hello(relay)
        self.assertEqual(37, len(hello))
        self.assertEqual(0x01, hello[0])
        self.assertEqual(relay, hub_module.parse_sockaddr(hello[1:17]))
        self.assertEqual(relay, hub_module.parse_sockaddr(hello[17:33]))
        request = hub_module.build_init_request(hub_module.SPECTATE_GAME_IDS[0])
        self.assertEqual(65, len(request))
        self.assertEqual(0x05, request[0])
        self.assertEqual(hub_module.SPECTATE_GAME_IDS[0], request[1:17])
        replay = hub_module.build_replay_request(4, 2)
        self.assertEqual(bytes([0x0E, 0x0B, 4, 0, 0, 0, 2]), replay)

    def test_region_database_result_maps_to_a_flag_key(self):
        self.assertEqual("cn", hub_module.parse_geo_country("120.229.26.50 [中国–广东–深圳 移动]"))
        self.assertEqual("hk", hub_module.parse_geo_country("203.198.0.1 [中国–香港 电讯盈科]"))
        self.assertEqual("tw", hub_module.parse_geo_country("168.95.1.1 [中国–台湾 中华电信]"))
        self.assertEqual("mo", hub_module.parse_geo_country("202.175.3.8 [中国–澳门 澳门电讯]"))
        self.assertEqual("jp", hub_module.parse_geo_country("133.242.10.1 [日本 CZ88.NET]"))
        self.assertEqual("us", hub_module.parse_geo_country("8.8.8.8 [美国–加利福尼亚州–圣克拉拉 谷歌]"))
        self.assertEqual("gb", hub_module.parse_geo_country("212.58.244.1 [英国–英格兰 伯克郡 BBC]"))
        self.assertEqual("", hub_module.parse_geo_country("no brackets here"))
        self.assertEqual("", hub_module.parse_geo_country("1.2.3.4 [未知地区]"))

    def test_hub_keeps_host_and_client_region_fields(self):
        self.publish(6002, 100, [dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                                      host_ip="120.229.26.50", client_ip="133.242.10.1",
                                      host_name="Host", client_name="Guest")])
        game = next(iter(self.hub.games.values()))
        self.assertEqual("120.229.26.50", game["host_ip"])
        self.assertEqual("133.242.10.1", game["client_ip"])
        # unknown addresses stay empty rather than raising
        self.assertEqual("", self.hub.resolve_country("not-an-ip"))
        self.assertEqual("", self.hub.resolve_country("127.0.0.1"))

    def test_lobby_log_lines_map_names_to_countries(self):
        hub = self.hub
        hub.consume_region_chunk(
            "2026-09-19 01:34:04,柍晽 120.229.26.50 [中国 广东 深圳 移动] (4eb8a627) <a8b6dc2d> has joined the lobby.\n"
            "2026-09-19 00:59:26,渣网小菜逼 219.104.161.228 [日本 东京都 CZ88.NET] (00000000) <0> has joined the lobby.\n"
            "8.134.214.80_45388 223.73.177.125 [中国 广东 深圳 阿里云] (8d65625f) <42a80a58> has joined the lobby.\n"
            "2026-09-19 02:03:42,Azuki_chan has disconnected\n"
            "2026-09-19 02:10:00,Azuki_chan 171.222.182.23 [中国 四川")
        self.assertEqual("cn", hub.player_countries["柍晽"])
        self.assertEqual("jp", hub.player_countries["渣网小菜逼"])
        self.assertEqual("cn", hub.player_countries["8.134.214.80_45388"])
        self.assertEqual("223.73.177.125", hub.player_ips["8.134.214.80_45388"])
        self.assertNotIn("Azuki_chan", hub.player_countries)
        # the trailing partial line is kept for the next chunk
        self.assertTrue(hub.region_pending.startswith("2026-09-19 02:10:00"))
        hub.consume_region_chunk(" 电信] (9a304af4) <638d09a1> has joined the lobby.\n")
        self.assertEqual("cn", hub.player_countries["Azuki_chan"])
        self.assertEqual("", hub.region_pending)

    def test_lobby_log_country_overrides_the_game_address_fallback(self):
        self.publish(6002, 100, [dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                                      host_name="A", client_name="B")])
        key = next(iter(self.hub.games))
        self.hub.games[key]["host_country"] = "us"      # e.g. resolved from a relay
        self.hub.consume_region_line(
            "2026-09-19 02:03:38,A 133.242.10.1 [日本 东京都 CZ88.NET] (x) <y> has joined the lobby.")
        self.hub.games[key]["host_country"] = self.hub.player_countries["A"]
        self.assertEqual("jp", self.hub.games[key]["host_country"])

    def test_ipv6_is_used_when_no_ipv4_endpoint_exists(self):
        try:
            root = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            root.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with root, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fallback, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            fallback.bind(("127.0.0.1", 0))
            viewer.bind(("127.0.0.1", 0))
            fallback.settimeout(0.1)
            root.settimeout(1)
            self.publish(6002, 100, [dict(machine=1, generation=1,
                host="not-an-ip", port=fallback.getsockname()[1],
                ipv6="::1", port6=root.getsockname()[1],
                host_name="Host", client_name="Guest")])
            key = next(iter(self.hub.games))
            hello = b"\x01" + hub_module.sockaddr(("43.136.23.115", self.relay_port)) * 2 + bytes.fromhex("000000bc")
            viewer.sendto(hello, ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            _, upstream = root.recvfrom(100)
            root.sendto(b"\x03", upstream)
            self.hub.receive_upstream(key, viewer.getsockname(), socket.AF_INET6)
            with self.assertRaises(socket.timeout):
                fallback.recvfrom(100)

    def test_failed_real_handshake_keeps_match_listed_for_debugging(self):
        game = dict(machine=1, generation=1, host="8.8.8.8", port=10800,
                    host_name="Host", client_name="Guest")
        self.publish(6002, 100, [game])
        key = next(iter(self.hub.games))
        self.hub.games[key]["viewers"][("1.2.3.4", 12345)] = dict(
            upstreams={socket.AF_INET: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)},
            last=time.monotonic(),
            actual_targets={}, pending_route=None, last_sent_route=self.relay_port,
            handshake_started=0, spectator_ready=False, last_init=None,
            first_hello=None, last_hello=None, root_hello_response=False,
            fallback_used=False, root_progress=False)
        viewer = self.hub.games[key]["viewers"][("1.2.3.4", 12345)]
        self.hub.selector.register(viewer["upstreams"][socket.AF_INET], 1,
                                   ("upstream", key, ("1.2.3.4", 12345), socket.AF_INET))
        self.hub.cleanup(time.monotonic())
        self.assertTrue(self.hub.games[key]["spectatable"])
        self.assertEqual(1, len(self.hub.list_games()))

    def test_udp_payload_is_forwarded_both_ways_unchanged(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            host.bind(("127.0.0.1", 0))
            viewer.bind(("127.0.0.1", 0))
            host.settimeout(1)
            viewer.settimeout(1)
            game = dict(machine=1, generation=1, host="127.0.0.1",
                        port=host.getsockname()[1], host_name="甲", client_name="乙")
            self.publish(6002, 100, [game])
            viewer.sendto(b"\x01\x02hello", ("127.0.0.1", self.relay_port))
            key = next(iter(self.hub.games))
            self.hub.receive_viewer(key)
            packet, upstream_address = host.recvfrom(100)
            self.assertEqual(b"\x01\x02hello", packet)
            host.sendto(b"\xffreply", upstream_address)
            self.hub.receive_upstream(key, viewer.getsockname())
            packet, relay_address = viewer.recvfrom(100)
            self.assertEqual(b"\xffreply", packet)
            self.assertEqual(self.relay_port, relay_address[1])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as alternate_host_port:
                alternate_host_port.bind(("127.0.0.1", 0))
                alternate_host_port.sendto(b"alternate", upstream_address)
                self.hub.receive_upstream(key, viewer.getsockname())
                self.assertEqual(b"alternate", viewer.recvfrom(100)[0])

    def test_redirect_and_child_punch_stay_inside_relay(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as child, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as child_reply, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as viewer:
            for sock in (host, child, child_reply, viewer):
                sock.bind(("127.0.0.1", 0))
                sock.settimeout(1)
            self.relay_port = free_udp_range(3)
            self.hub.ports = range(self.relay_port, self.relay_port + 3)
            self.publish(6002, 100, [dict(machine=1, generation=1,
                                            host="127.0.0.1", port=host.getsockname()[1],
                                            host_name="Host", client_name="Guest")])
            key = next(iter(self.hub.games))
            viewer_address = viewer.getsockname()
            upstream_address = None
            viewer.sendto(b"\x01" + hub_module.sockaddr(("43.136.23.115", self.relay_port)) * 2
                          + b"\x00\x00\x00\xbc", ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            _, upstream_address = host.recvfrom(100)
            host.sendto(b"\x03", upstream_address)
            self.hub.receive_upstream(key, viewer_address)
            self.assertEqual(b"\x03", viewer.recvfrom(100)[0])

            viewer.sendto(b"\x05request", ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            host.recvfrom(100)
            redirect_extra = bytes.fromhex("000040c00000a0c0")
            redirect = (b"\x08" + (1).to_bytes(4, "little") +
                        hub_module.sockaddr(child.getsockname())[:8] + redirect_extra + b"\x00" * 48)
            host.sendto(redirect, upstream_address)
            self.hub.receive_upstream(key, viewer_address)
            rewritten, source = viewer.recvfrom(100)
            self.assertEqual(self.relay_port, source[1])
            self.assertEqual(2, len(self.hub.games[key]["routes"]),
                             (list(self.hub.games[key]["routes"]), list(self.hub.ports),
                              child.getsockname(), self.hub.allow_private_targets))
            child_relay = hub_module.parse_sockaddr(rewritten[5:21])
            self.assertEqual("43.136.23.115", child_relay[0])
            self.assertNotEqual(self.relay_port, child_relay[1])
            self.assertEqual(redirect_extra, rewritten[13:21])

            punch_hello = (b"\x01" + hub_module.sockaddr(("43.136.23.115", self.relay_port))
                           + hub_module.sockaddr(child_relay) + b"\x00\x00\x00\xbc")
            viewer.sendto(punch_hello, ("127.0.0.1", self.relay_port))
            self.hub.receive_viewer(key)
            forwarded, _ = host.recvfrom(100)
            self.assertEqual(host.getsockname(), hub_module.parse_sockaddr(forwarded[1:17]))
            self.assertEqual(child.getsockname(), hub_module.parse_sockaddr(forwarded[17:33]))

            # NAT may change the child's source port after the parent's PUNCH.
            child_reply.sendto(b"\x03", upstream_address)
            self.hub.receive_upstream(key, viewer_address)
            packet, source = viewer.recvfrom(100)
            self.assertEqual(b"\x03", packet)
            self.assertEqual(child_relay[1], source[1])

            viewer.sendto(b"\x05child", ("127.0.0.1", child_relay[1]))
            self.hub.receive_viewer(key, child_relay[1])
            self.assertEqual(b"\x05child", child_reply.recvfrom(100)[0])
            child_reply.sendto(b"\x06accepted", upstream_address)
            self.hub.receive_upstream(key, viewer_address)
            packet, source = viewer.recvfrom(100)
            self.assertEqual(b"\x06accepted", packet)
            self.assertEqual(child_relay[1], source[1])

            self.hub.games[key]["viewers"][viewer_address]["last"] = 0
            self.hub.games[key]["routes"][child_relay[1]]["last"] = 0
            self.hub.cleanup(time.monotonic())
            self.assertNotIn(child_relay[1], self.hub.games[key]["routes"])


if __name__ == "__main__":
    unittest.main()
