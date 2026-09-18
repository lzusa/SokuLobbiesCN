# Shared spectator hub

`spectator_hub.py` is a single service shared by every `SokuLobbiesServer`
process on the same host. Lobby processes publish complete snapshots every
three seconds to `127.0.0.1:18081`; no per-lobby configuration is required.
The hub expires a lobby after twelve seconds without a snapshot, so a crashed
lobby cannot leave stale games indefinitely.

The public API is `GET /games` and `PUT /games` on TCP/5500. It preserves the
fields consumed by the current client. Started games are assigned ports in
UDP/5501-5599. Each spectator has a separate upstream UDP socket, while the
downstream endpoint remains the same public match port. Game datagrams are
forwarded unchanged. The hub intentionally does not parse game packets.

Deploy `spectator_hub.py` to `/opt/soku-spectator-hub/`, install the example
systemd unit, and allow public TCP/5500 and UDP/5501-5599 in both the
system and cloud firewalls. Keep UDP/18081 loopback-only. Set `--public-ip` to
the server's real public IPv4; when a cloud NAT maps a private bind address to
that IPv4, the public UDP port range must be mapped without port translation.
Start the hub before restarting lobby servers. Check `/games` from an external
client before switching the client `HostlistUrl` setting. Hostlist PUT entries
are kept for fifteen minutes; started-game entries depend on live lobby
snapshots. Existing clients with Konni hardcoded cannot use the new list.

No service deployment or firewall change is performed by merely building this
repository.
