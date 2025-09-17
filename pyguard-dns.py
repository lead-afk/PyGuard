#!/usr/bin/env python3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dnslib import DNSRecord, QTYPE
from dnslib import RR, A, AAAA
import os
import socket
import struct
import threading
import ipaddress
from pyguard import BASE_DATA_DIR, list_interfaces, is_interface_active, load_data


def resolve_domain(domain, dns_server="8.8.8.8"):
    """
    Resolve a domain name to an IPv4 address using a given DNS server.

    :param domain: str - domain name (e.g., "example.com")
    :param dns_server: str - DNS server IP (default: 8.8.8.8)
    :return: str - resolved IP address or None
    """
    q = DNSRecord.question(domain, qtype=QTYPE.A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(q.pack(), (dns_server, 53))
        data, _ = sock.recvfrom(512)
        reply = DNSRecord.parse(data)
        for rr in reply.rr:
            if rr.rtype == QTYPE.A:  # IPv4
                return str(rr.rdata)
    except Exception as e:
        print("Error:", e)
    finally:
        sock.close()
    return None


def build_dns_response(data, records, upstream_dns="1.1.1.1"):
    # DNS Header: transaction ID, flags, counts
    tid = data[:2]  # transaction ID
    flags = b"\x81\x80"  # standard response, recursion not available
    qdcount = data[4:6]  # number of questions
    ancount = b"\x00\x01"  # one answer
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = tid + flags + qdcount + ancount + nscount + arcount

    # Question section (copy from request)
    query = data[12:]
    # Name is variable length → copy until 0x00
    end = query.find(b"\x00") + 5  # domain + null + QTYPE(2) + QCLASS(2)
    question = query[:end]
    # Also produce a human-readable representation of the question
    try:
        # parse labels (sequence of length-prefixed strings)
        labels = []
        i = 0
        while i < len(question):
            length = question[i]
            if length == 0:
                i += 1
                break
            labels.append(
                question[i + 1 : i + 1 + length].decode("ascii", errors="replace")
            )
            i += 1 + length

        domain = ".".join(labels) if labels else ""
        # Next two bytes = QTYPE, following two = QCLASS (network byte order)
        qtype = None
        qclass = None
        if i + 4 <= len(question):
            qtype = struct.unpack("!H", question[i : i + 2])[0]
            qclass = struct.unpack("!H", question[i + 2 : i + 4])[0]

        question_str = f"{domain} QTYPE={qtype} QCLASS={qclass}"
    except Exception:
        question_str = "<unparseable>"

    # Upstream resolver (IP:port) configurable via env
    upstream = upstream_dns
    if ":" in upstream:
        up_host, up_port = upstream.split(":", 1)
        up_port = int(up_port)
    else:
        up_host = upstream
        up_port = 53

    try:
        req = DNSRecord.parse(data)
    except Exception:
        # Malformed request; just return empty
        return b""

    if not req.questions:
        return b""

    q = req.questions[0]
    qname = str(q.get_qname()).rstrip(".")
    qtype = q.qtype  # numeric

    # Normalize records to iterable of (name, ip)
    if hasattr(records, "items"):
        items = list(records.items())
    else:
        items = list(records)

    # Find matching local records (case-insensitive)
    matching = [r for r in items if r[0].rstrip(".").lower() == qname.lower()]

    # If we have a matching record and the query type is A or AAAA, answer locally
    if matching and qtype in (QTYPE.A, QTYPE.AAAA):
        # Prefer an address with the correct family
        chosen_ip = None
        for _, ip in matching:
            try:
                ip_obj = ipaddress.ip_address(ip)
            except Exception:
                continue
            if qtype == QTYPE.A and isinstance(ip_obj, ipaddress.IPv4Address):
                chosen_ip = ip
                break
            if qtype == QTYPE.AAAA and isinstance(ip_obj, ipaddress.IPv6Address):
                chosen_ip = ip
                break

        # If not found with exact family, fall back to first matching IP that can be coerced
        if not chosen_ip and matching:
            chosen_ip = matching[0][1]

        if chosen_ip:
            reply = req.reply()
            try:
                if qtype == QTYPE.A:
                    reply.add_answer(
                        RR(q.get_qname(), QTYPE.A, rdata=A(chosen_ip), ttl=60)
                    )
                else:
                    reply.add_answer(
                        RR(q.get_qname(), QTYPE.AAAA, rdata=AAAA(chosen_ip), ttl=60)
                    )
                return reply.pack()
            except Exception:
                # If dnslib packing fails, fallthrough to forwarding
                pass

    # No local answer -> forward to upstream resolver and return response
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.sendto(data, (up_host, up_port))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        return resp
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return b""


class DNSServer:
    def __init__(self, ip: str, records: dict[str, str], upstream_dns: str = "1.1.1.1"):
        self.ip = ip
        # self.ip = "0.0.0.0"
        self.records = records
        self.records_lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, 53))
        # self.sock.bind(("0.0.0.0", 53))
        self.running = True
        self.upstream_dns = upstream_dns
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while self.running:
            data, addr = self.sock.recvfrom(512)
            with self.records_lock:
                response = build_dns_response(
                    data, self.records, upstream_dns=self.upstream_dns
                )
            self.sock.sendto(response, addr)

    def stop(self):
        self.running = False
        self.sock.close()
        self.thread.join()

    def start(self):
        if not self.running:
            self.__init__(self.ip, self.records)

    def restart(self):
        self.stop()
        self.__init__(self.ip, self.records)

    def update_records(self, records: dict[str, str]):
        with self.records_lock:
            self.records = records

    def update_upstream_dns(self, dns_server: str):
        with self.records_lock:
            self.upstream_dns = dns_server


main_dict = {}


def reload_dns_config(specific_iface=None):

    interfaces = list_interfaces()
    for iface in interfaces:
        if specific_iface and iface["name"] != specific_iface:
            continue
        if iface.get("active", False):
            name = iface["name"]
            data = load_data(name)

            # if not data.get("dns_service", False) and False:  # Disabled for now
            #     continue

            new_records = {f"relay.{name}": data.get("server", {}).get("ip")}
            for peer_name in data.get("peers", {}):
                peer = data.get("peers", {}).get(peer_name, {})
                ip = peer.get("ip")
                if ip:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            new_records[str(peer_name) + "." + str(name)] = str(ip)
                    except ValueError:
                        continue

            network = data.get("server", {}).get("network")
            if not network:
                continue

            same = True

            if network not in main_dict:
                main_dict[network] = {}
                same = False

            existing_records = main_dict[network].get("records", [])

            if set(new_records) != set(existing_records):
                print("Records sets differ")
                same = False

            print(f"DNS records for {network} ({name}): {new_records}")

            if not same:
                main_dict[network]["records"] = new_records
                if not main_dict[network].get("dns_server"):
                    print(f"Starting DNS server on {network} ({name})")
                    dns_ip = data.get("server", {}).get("ip")
                    main_dict[network]["dns_server"] = DNSServer(
                        ip=dns_ip, records=new_records
                    )
                elif main_dict[network].get("dns_server"):
                    print(f"Restarting DNS server on {network} ({name})")
                    main_dict[network]["dns_server"].update_records(new_records)
            else:
                print(f"No changes for DNS server on {network} ({name})")

            if not main_dict[network].get("dns_server"):
                print(f"Starting DNS server on {network} ({name})")
                dns_ip = data.get("server", {}).get("ip")
                main_dict[network]["dns_server"] = DNSServer(
                    ip=dns_ip, records=new_records
                )

            if main_dict[network].get("dns_server").upstream_dns != data.get(
                "server", {}
            ).get("dns"):
                print(f"Updating upstream DNS server on {network} ({name})")
                main_dict[network]["dns_server"].update_upstream_dns(
                    data.get("server", {}).get("dns")
                )

        else:
            print(
                f"Interface {iface['name']} is not active, stopping DNS server if running."
            )
            data = load_data(iface["name"])
            network = data.get("server", {}).get("network")
            if network and main_dict.get(network):
                if main_dict[network].get("dns_server"):
                    main_dict[network]["dns_server"].stop()
                    del main_dict[network]["dns_server"]
                del main_dict[network]


class ChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(".conf"):
            name = event.src_path.split("/")[-1]
            name = name.replace(".conf", "")
            threading.Thread(target=reload_dns_config, args=(name,)).start()

    def on_created(self, event):
        if event.src_path.endswith(".conf"):
            name = event.src_path.split("/")[-1]
            name = name.replace(".conf", "")
            print(f"Interface {name} changed and is active, reloading DNS config.")
            threading.Thread(target=reload_dns_config, args=(name,)).start()


def main():
    reload_dns_config()

    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=BASE_DATA_DIR, recursive=True)
    observer.start()

    while True:
        try:
            pass
        except KeyboardInterrupt:
            break

    observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
