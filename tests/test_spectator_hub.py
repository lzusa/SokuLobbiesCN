import importlib.util
import json
import socket
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
        sockaddr = b"\x02\x00" + relay[1].to_bytes(2, "big") + \
            socket.inet_aton(relay[0]) + b"\x00" * 8
        hello = b"\x01" + sockaddr + sockaddr + b"\x00\x00\x00\xbc"
        converted = hub_module.rewrite_hello_target(hello, relay, target)
        expected = b"\x02\x00" + target[1].to_bytes(2, "big") + \
            socket.inet_aton(target[0]) + b"\x00" * 8
        self.assertEqual(b"\x01" + expected + expected + hello[-4:], converted)
        self.assertEqual(hello, hub_module.rewrite_hello_target(hello, ("1.2.3.4", 20000), target))

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


if __name__ == "__main__":
    unittest.main()


