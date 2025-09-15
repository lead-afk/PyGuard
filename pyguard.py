#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import ipaddress
import stat
from pathlib import Path
import shutil
import re
import psutil
from enum import Enum

# Constants / Paths
CONFIG_DIR = "/etc/wireguard"  # Actual WireGuard runtime configs generated
BASE_DATA_DIR = (
    "/etc/pyguard"  # PyGuard state (per-interface JSON now named <iface>.conf)
)
SETTINGS_FILE = os.path.join(BASE_DATA_DIR, "settings")
DEFAULT_INTERFACE = "wg0"  # Only used as a default when creating new data
DEFAULT_PORT = 51820
DEFAULT_NETWORK = "10.0.0.0/24"
DEFAULT_DNS = "1.1.1.1"
DEFAULT_ALLOWED_IPS = None  # Dynamically uses server network for clients if None
SCRIPT_PATH = os.path.abspath(__file__)


# Deprecated legacy layout helpers (migration support)
def legacy_data_path(interface: str) -> str:
    """Return the legacy data file path for a given interface.

    Args:
        interface: The WireGuard interface name

    Returns:
        Path to the legacy JSON file for the interface
    """
    return f"{BASE_DATA_DIR}/peers-{interface}.json"


def data_path(interface: str) -> str:
    """Return new per-interface state file path (<iface>.conf).

    Args:
        interface: The WireGuard interface name

    Returns:
        Path to the current JSON configuration file for the interface
    """
    return f"{BASE_DATA_DIR}/{interface}.conf"


class Settings(Enum):
    allow_command_apply = False  # Allow the api to apply ufw rules


def load_settings():
    """Load settings from the configuration file."""
    settings = {}
    for setting in Settings:
        settings.setdefault(setting.name, setting.value)

    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w") as f:
            for key, value in settings.items():
                f.write(f"{key}={value}\n")

        return settings

    with open(SETTINGS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().lower()
                if value in ("true", "1", "yes", "on"):
                    value = True
                elif value in ("false", "0", "no", "off"):
                    value = False
                else:
                    try:
                        value = Settings[key]
                    except KeyError:
                        pass

                settings[key] = value

    return settings


def ensure_root():
    """Exit if not root on POSIX systems (WireGuard + file permissions require root).

    Raises:
        SystemExit: If not running as root user
    """
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)


def ensure_directories():
    """Create necessary directories for PyGuard configuration and WireGuard configs.

    Creates:
        - BASE_DATA_DIR: Directory for PyGuard state files
        - CONFIG_DIR: Directory for WireGuard configuration files
    """
    os.makedirs(BASE_DATA_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)


def migrate_if_legacy(interface: str):
    """If a legacy peers-<iface>.json exists and new <iface>.conf does not, migrate it.

    Args:
        interface: The WireGuard interface name to check for migration

    Note:
        Copies the legacy file to the new location and preserves permissions.
        The legacy file is kept for safety.
    """
    legacy = legacy_data_path(interface)
    new = data_path(interface)
    if os.path.exists(legacy) and not os.path.exists(new):
        try:
            shutil.copy2(legacy, new)
            os.chmod(new, stat.S_IRUSR | stat.S_IWUSR)
            # Keep legacy file for now (safer). Could delete after confirmed working.
        except Exception as e:
            print(f"Warning: failed migrating legacy data file {legacy} -> {new}: {e}")


def list_interfaces(as_json: bool = False, print_output: bool = False):  # ???
    """List interfaces with optional JSON output.

    Args:
        as_json: If True, return detailed interface information as JSON-serializable data
        print_output: If True, print the interface list to stdout

    Returns:
        List of interface names (if as_json=False) or list of detail dicts (if as_json=True)
        Each detail dict contains: name, port, network, public_ip, peer_count, active
    """
    try:
        entries = os.listdir(BASE_DATA_DIR)
    except FileNotFoundError:
        entries = []
    names = []
    details = []
    for fname in entries:
        if not fname.endswith(".conf"):
            continue
        iface = fname[:-5]
        names.append(iface)
        try:
            data = load_data(iface)
            active = is_interface_active(iface)
            srv = data.get("server", {})
            details.append(
                {
                    "name": iface,
                    "port": srv.get("port", 0),
                    "network": srv.get("network", "0.0.0.0/0"),
                    "public_ip": srv.get("public_ip", "0.0.0.0"),
                    "peer_count": len(data.get("peers", {})),
                    "active": active,
                    "launch_on_start": data.get("launch_on_start", False),
                }
            )
        except Exception:
            print(f"Warning: could not load data for interface {iface}")
    names.sort()
    details.sort(key=lambda d: d.get("name"))

    if print_output:
        if not as_json:
            if not names:
                print("No interfaces initialized")
            else:
                print("Interfaces:")
                for d in details:
                    if "error" in d:
                        print(f"  {d['name']} (error loading data)")
                    else:
                        print(
                            f"  {d['name']} (port {d['port']}, network {d['network']}), peers: {d['peer_count']}, active: {d['active']})"
                        )
        else:
            print(json.dumps({"interfaces": details}, indent=2))
    return details


def command_exists(cmd: str) -> bool:
    """Check if a command exists in the system PATH.

    Args:
        cmd: The command name to check

    Returns:
        True if the command exists, False otherwise
    """
    return shutil.which(cmd) is not None


def get_new_interface_defaults():
    """Generate default values for a new WireGuard interface.

    Returns:
        Tuple of (interface_name, port, network, public_ip) with auto-selected values
        that don't conflict with existing interfaces or system resources.

    Raises:
        ValueError: If no available ports or IP ranges can be found
    """
    ensure_root()
    used_interfaces = os.listdir("/etc/wireguard/")
    used_pyguard_interfaces = os.listdir("/etc/pyguard/")

    i = 0
    while True:
        iface = f"wg{i}.conf"
        if iface not in used_interfaces and iface not in used_pyguard_interfaces:
            name = iface[:-5]
            break
        i += 1

    i = 51820
    used_ports = get_used_ports()
    used_ip_ranges = list(get_used_ip_ranges())

    for interface in used_pyguard_interfaces:
        iName = interface.split(".")[0]
        try:
            data = load_data(iName)
            if not data:
                continue
        except Exception as e:
            print(f"Warning: could not load data for interface {iName}: {e}")
            continue

        port = data.get("server", {}).get("port")
        if port:
            used_ports.append(port)
            used_ip_ranges.append(
                ipaddress.ip_network(data.get("server", {}).get("network"))
            )

    while True:
        if i not in used_ports:
            port = i
            break
        if i == 51819:
            raise ValueError("No available ports found.")
        i = (i + 1) % 65536
        if i < 1000:
            i = 1001

    # print(used_ip_ranges)
    base_network = [10, 0, 0, 0]

    while True:
        ok = True
        for used in used_ip_ranges:
            if ipaddress.ip_network(
                f"{base_network[0]}.{base_network[1]}.{base_network[2]}.0/24"
            ).overlaps(used):
                ok = False
                break
        if ok:
            network = f"{base_network[0]}.{base_network[1]}.{base_network[2]}.0/24"
            break
        base_network[2] += 1
        if base_network[2] > 255:
            base_network[2] = 0
            base_network[1] += 1
        if base_network[1] > 255:
            base_network[1] = 0
            base_network[0] += 1
        if base_network[0] > 255:
            raise ValueError("No available IP ranges found.")

    public_ip = get_public_ip()

    return name, port, network, public_ip


def ensure_qrencode_installed():
    """Ensure qrencode CLI is installed. On Debian/Ubuntu, install via apt-get if missing.

    Attempts to automatically install qrencode using apt-get if available.
    Provides installation instructions for other package managers if apt-get is not available.
    """
    if command_exists("qrencode"):
        return
    print("qrencode not found. Attempting to install via apt-get ...")
    # Only attempt on systems with apt-get
    if not command_exists("apt-get"):
        print(
            "apt-get not available. Please install 'qrencode' using your package manager."
        )
        print(
            "Examples: 'sudo apt-get install qrencode' or 'sudo dnf install qrencode' or 'sudo pacman -S qrencode'"
        )
        return
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    try:
        subprocess.run(
            ["apt-get", "update"],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(["apt-get", "install", "-y", "qrencode"], check=True, env=env)
        if command_exists("qrencode"):
            print("qrencode installed successfully.")
        else:
            print(
                "Attempted to install qrencode, but it still isn't available. Please install manually."
            )
    except Exception as e:
        print(f"Failed to install qrencode automatically: {e}")
        print("Please install 'qrencode' using your package manager and re-run.")


def ensure_secret_jwt():
    ensure_root()
    path_to_key = os.path.join(BASE_DATA_DIR, "secret.key")
    """Ensure a stable, ASCII JWT secret shared across processes.

    Previous implementation stored raw random bytes; reading them as text could
    produce inconsistencies or decoding issues. This version guarantees the
    secret is a URL-safe base64 string (without trailing newlines) and migrates
    any existing binary file automatically.
    """
    ensure_root()
    path_to_key = os.path.join(BASE_DATA_DIR, "secret.key")
    os.makedirs(BASE_DATA_DIR, exist_ok=True)

    def _write_secret(b64_secret: str):
        with open(path_to_key, "w", encoding="utf-8") as f:
            f.write(b64_secret)
        os.chmod(path_to_key, stat.S_IRUSR | stat.S_IWUSR)

    import base64, string

    if not os.path.exists(path_to_key):
        raw = os.urandom(32)
        b64 = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
        _write_secret(b64)
        secret = b64
    else:
        # Read in binary; decide if migration required
        with open(path_to_key, "rb") as f:
            content = f.read()
        try:
            text = content.decode("utf-8").strip()
        except UnicodeDecodeError:
            text = ""  # force migration
        printable = set(string.printable)
        needs_migration = (
            not text
            or any(c not in printable for c in text)
            or len(text) < 16  # unusually short for our base64 secret
        )
        if needs_migration:
            # Re-base64 the raw bytes to produce a clean ascii secret
            b64 = base64.urlsafe_b64encode(content).decode("utf-8").rstrip("=")
            _write_secret(b64)
            secret = b64
        else:
            secret = text
    os.environ["JWT_SECRET_KEY"] = secret
    return secret


def ensure_wireguard_installed():
    """Ensure WireGuard is installed. On Debian/Ubuntu, install via apt-get if missing.

    Attempts to automatically install WireGuard using apt-get if available.
    Provides installation instructions for other package managers if apt-get is not available.
    """
    if command_exists("wg"):
        return
    print("WireGuard not found. Attempting to install via apt-get ...")
    # Only attempt on systems with apt-get
    if not command_exists("apt-get"):
        print(
            "apt-get not available. Please install 'wireguard' using your package manager."
        )
        print(
            "Examples: 'sudo apt-get install wireguard' or 'sudo dnf install wireguard' or 'sudo pacman -S wireguard'"
        )
        return
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    try:
        subprocess.run(
            ["apt-get", "update"],
            check=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(["apt-get", "install", "-y", "wireguard"], check=True, env=env)
        if command_exists("wg"):
            print("WireGuard installed successfully.")
        else:
            print(
                "Attempted to install WireGuard, but it still isn't available. Please install manually."
            )
    except Exception as e:
        print(f"Failed to install WireGuard automatically: {e}")
        print("Please install 'wireguard' using your package manager and re-run.")


def ensure_core_installed():
    """Ensure core WireGuard components are installed.

    Currently ensures WireGuard is installed. Can be extended to check
    for other core dependencies as needed.
    """
    ensure_wireguard_installed()


def load_data(interface: str) -> dict:
    """Load (or initialize) data for the specified interface.

    Performs migration from legacy peers-<iface>.json naming if necessary.

    Args:
        interface: The WireGuard interface name

    Returns:
        Dictionary containing server and peers configuration data.
        If no existing data is found, returns a default configuration structure.

    Raises:
        ValueError: If the JSON file is corrupted
        Exception: If the file cannot be loaded for other reasons
    """

    DEFAULT_SERVER = {
        "server": {
            "private_key": "",
            "public_key": "",
            "interface": interface,
            "port": DEFAULT_PORT,
            "network": DEFAULT_NETWORK,
            "dns": DEFAULT_DNS,
            "public_ip": "",
            "custom_post_up": [],
            "custom_post_down": [],
        },
        "peers": {},
        "launch_on_start": False,
        "dns_service": False,
        "forward_to_docker_bridge": False,
        "allow_vpn_gateway": False,
    }

    ensure_directories()
    migrate_if_legacy(interface)
    path = data_path(interface)
    if not os.path.exists(path):
        return DEFAULT_SERVER
    try:
        with open(path, "r") as f:
            data = json.load(f)
        # Backfill newer fields if missing
        server = data.setdefault("server", {})
        server.setdefault("custom_post_up", [])
        server.setdefault("custom_post_down", [])
        server.setdefault("public_ip", "")
        server.setdefault("interface", interface)
        data.setdefault("peers", {})
        data.setdefault("launch_on_start", False)
        data.setdefault("dns_service", False)
        data.setdefault("forward_to_docker_bridge", False)
        data.setdefault("allow_vpn_gateway", False)
        return data
    except json.JSONDecodeError:
        print(f"Error: state file for {interface} is corrupted ({path})")
        raise ValueError(f"Invalid JSON format, in file {path}")
    except Exception as e:
        print(f"Error loading data for {interface}: {e}")
        raise Exception(f"Failed loading data for {interface}: {e}")


def _parse_handshake_to_seconds(handshake_str: str) -> int | None:
    """Convert WireGuard handshake text into seconds.

    Args:
        handshake_str: Human-readable handshake time string from WireGuard
                      Examples: "1 minute, 30 seconds ago", "2 days ago", "now"

    Returns:
        Number of seconds since last handshake, or None if parsing fails.
        Returns 0 for "now".

    Example:
        >>> _parse_handshake_to_seconds("1 minute, 30 seconds ago")
        90
    """
    if handshake_str.strip() == "now":
        return 0

    total_seconds = 0
    # Regex matches "2 days", "1 hour", "30 seconds"
    matches = re.findall(
        r"(\d+)\s+(day|days|hour|hours|minute|minutes|second|seconds)", handshake_str
    )

    multipliers = {
        "day": 86400,
        "days": 86400,
        "hour": 3600,
        "hours": 3600,
        "minute": 60,
        "minutes": 60,
        "second": 1,
        "seconds": 1,
    }

    for num, unit in matches:
        total_seconds += int(num) * multipliers[unit]

    return total_seconds if total_seconds > 0 else None


def get_peers_info(interface: str, specific_peer: str = None):
    """Parse `wg show <interface>` and return peers info.

    Args:
        interface: WireGuard interface name (e.g. 'wg0')
        specific_peer: If provided, filter results to this peer only

    Returns:
        Dictionary containing peer information mapped by peer name.
        Each peer entry includes: last_handshake, last_handshake_str, active,
        download, uploaded, endpoint data.

        If specific_peer is provided, returns data for that peer only.
        If specific_peer doesn't exist, returns empty dict for that peer.
    """
    ensure_root()  # make sure we are root before calling wg

    result = subprocess.run(
        ["wg", "show", interface], capture_output=True, text=True, check=False
    )
    lines = result.stdout.splitlines()

    DEFAULT_PEER_DATA = {
        "last_handshake": 600,
        "last_handshake_str": "never",
        "active": False,
        "download": "0.0 KiB",
        "uploaded": "0.0 KiB",
        "endpoint": "0.0.0.0/0",
    }

    peers = {}
    current_peer = None

    for line in lines:
        line = line.strip()
        if line.startswith("peer:"):
            current_peer = line.split()[1]
            peers[current_peer] = DEFAULT_PEER_DATA.copy()
        elif line.startswith("endpoint") and current_peer:
            peers[current_peer]["endpoint"] = line.split(":", 1)[1].strip()
        elif line.startswith("latest handshake:") and current_peer:
            hs_str = line.split(":", 1)[1].strip()
            hs_seconds = _parse_handshake_to_seconds(hs_str)
            peers[current_peer]["last_handshake"] = (
                hs_seconds if hs_seconds is not None else 600
            )
            peers[current_peer]["last_handshake_str"] = hs_str

            if peers[current_peer]["last_handshake"] < 600:
                peers[current_peer]["active"] = True

        elif line.startswith("transfer:") and current_peer:
            parts = line.split()
            try:
                recv = parts[1] + " " + parts[2]  # e.g. "1.23 MiB"
                sent = parts[4] + " " + parts[5]  # e.g. "4.56 MiB"
                peers[current_peer]["download"] = recv
                peers[current_peer]["uploaded"] = sent
            except IndexError:
                pass

    # Map peers to your data source
    toReturn = {}
    data = load_data(interface)
    peersJson = data.get("peers", {})
    if specific_peer:
        peersJson = {specific_peer: peersJson.get(specific_peer, {})}
    for peer in peersJson.keys():
        for pub_key in peers.keys():
            if peersJson[peer].get("public_key") == pub_key:
                toReturn[peer] = peers[pub_key]
                break

        if peer not in toReturn:
            toReturn[peer] = DEFAULT_PEER_DATA.copy()

    if specific_peer and specific_peer not in toReturn:
        toReturn[specific_peer] = {}
    elif specific_peer:
        toReturn = toReturn.get(specific_peer, {})

    return toReturn


def save_data(interface: str, data: dict):
    """Save interface configuration data to disk.

    Args:
        interface: The WireGuard interface name
        data: Configuration data dictionary to save

    Raises:
        SystemExit: If saving fails for any reason
    """
    try:
        path = data_path(interface)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        print(f"Error saving data for {interface}: {e}")
        print("Data not saved.")
        print(data)
        raise Exception("Data not saved.")


def delete_interface(interface: str):
    """Delete PyGuard state + generated WireGuard config + systemd service for an interface.

    Args:
        interface: The WireGuard interface name to delete

    Note:
        Attempts to safely bring down the interface before deletion.
        Removes state files, WireGuard configs, and systemd services.
        Continues with cleanup even if some steps fail.
    """
    ensure_root()
    # Attempt to bring interface down (ignore errors)
    try:
        subprocess.run(
            ["wg-quick", "down", interface],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        pass
    # Remove state file
    state_file = data_path(interface)
    if os.path.exists(state_file):
        try:
            os.remove(state_file)
            print(f"Removed state file: {state_file}")
        except Exception as e:
            print(f"Warning: could not remove state file {state_file}: {e}")
    # Remove generated WireGuard config
    wg_conf = os.path.join(CONFIG_DIR, f"{interface}.conf")
    if os.path.exists(wg_conf):
        try:
            os.remove(wg_conf)
            print(f"Removed WireGuard config: {wg_conf}")
        except Exception as e:
            print(f"Warning: could not remove WireGuard config {wg_conf}: {e}")
    # Remove systemd service
    if command_exists("systemctl"):
        service_name = f"pyguard-{interface}.service"
        service_path = f"/etc/systemd/system/{service_name}"
        try:
            subprocess.run(["systemctl", "stop", service_name], check=False)
            subprocess.run(["systemctl", "disable", service_name], check=False)
            if os.path.exists(service_path):
                os.remove(service_path)
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            print(f"Removed systemd service (if existed): {service_name}")
        except Exception as e:
            print(
                f"Warning: could not fully remove systemd service for {interface}: {e}"
            )
    print(f"Interface '{interface}' deleted.")


def generate_keypair():
    """Generate WireGuard key pair.

    Returns:
        Tuple of (private_key, public_key) as strings

    Raises:
        subprocess.CalledProcessError: If key generation fails
    """
    private_key = (
        subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    )
    public_key = (
        subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True)
        .decode("utf-8")
        .strip()
    )
    return private_key, public_key


def is_ip(s: str) -> bool:
    """Check if a string is a valid IP address.

    Args:
        s: String to validate as an IP address

    Returns:
        True if the string is a valid IPv4 or IPv6 address, False otherwise
    """
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def get_next_ip(interface: str, custom_network: str = None):
    """Get the next available IP in the network.

    Args:
        interface: The WireGuard interface name
        custom_network: Optional custom network CIDR to use instead of interface default

    Returns:
        String representation of the next available IP address

    Raises:
        SystemExit: If network is invalid or no available IPs found
    """
    data = load_data(interface)

    try:
        if custom_network is None:
            network = ipaddress.ip_network(data.get("server", {}).get("network"))
        else:
            network = ipaddress.ip_network(custom_network)
    except ValueError as e:
        print(f"Error: Invalid network: {e}")
        raise Exception(f"Invalid network: {e}")

    used_ips = [network.hosts().__next__().exploded]  # Start with server IP

    for peer in data.get("peers", {}).values():
        used_ips.append(peer.get("ip"))

    for ip in network.hosts():
        if str(ip) not in used_ips:
            return str(ip)

    raise Exception("No available IPs in the network")


def get_local_gateway():  # TODO  what if in docker but network mode is host?
    result = subprocess.run(
        ["ip", "route"],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = result.stdout.splitlines()
    print(lines)
    for line in lines:
        line = line.strip()
        if line.startswith("default via"):
            parts = line.split()
            try:
                gateway = ipaddress.ip_address(parts[2])
                name = parts[4]
                print(f"Detected local gateway IP: {gateway}")
                return str(gateway), str(name)
            except Exception:
                continue
    print("Warning: could not determine docker bridge IP, defaulting to 172.16.0.1")
    return "172.16.0.1", "not-found"


def get_used_network_names():
    return [iface for iface, addrs in psutil.net_if_addrs().items()]


def get_used_ip_ranges(verbose: bool = False):
    """Return a list of CIDR ranges (subnets) for all local interfaces.

    Returns:
        Set of ipaddress.IPv4Network or ipaddress.IPv6Network objects
        representing all network ranges currently in use by the system
    """
    ranges = set()

    for iface, addrs in psutil.net_if_addrs().items():
        if verbose:
            print(f"Interface: {iface}, Addresses: {addrs}")
        for addr in addrs:
            if addr.family.name in ("AF_INET", "AF_INET6"):
                ip = addr.address
                netmask = addr.netmask

                if ip and netmask:
                    try:
                        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                        ranges.add(network)
                    except ValueError:
                        continue

    return ranges


def get_public_ip():
    """Retrieve the public IP address of the server.

    Returns:
        String containing the public IP address, or "<unknown>" if retrieval fails

    Note:
        Uses 'curl ifconfig.me' to determine the public IP address.
        Falls back to "<unknown>" if the service is unavailable.
    """

    result = None
    try:
        result = subprocess.run(
            ["curl", "ifconfig.me"], capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError:
        pass

    toReturn = result.stdout.strip() if result else "<unknown>"

    return toReturn


def validate_new_interface(
    interface: str,
    port: int,
    network: str,
    ignore_range_check: bool = True,
    ignore_name: bool = False,
    ignore_port: bool = False,
    ignore_network: bool = False,
):
    """Validate server configuration.

    Args:
        interface: The WireGuard interface name to validate
        port: Port number to validate
        network: Network CIDR to validate
        ignore_range_check: If True, skip checking for network range overlaps
        ignore_name: If True, skip checking if interface name already exists
        ignore_port: If True, skip checking if port is already in use
        ignore_network: If True, skip network validation entirely

    Returns:
        Tuple of (success: bool, metadata: dict)
        metadata contains either {"success": True} or {"error": "error message"}
    """
    ensure_root()
    data = load_data(interface)
    existing_interfaces = os.listdir("/etc/wireguard/")
    if not ignore_name and (
        data.get("server", {}).get("private_key")
        or (interface + ".conf") in existing_interfaces
        or interface in get_used_network_names()
    ):
        return False, {"error": f"Server {interface} already exists or name in use"}
    if not ignore_port and port in get_used_ports():
        return False, {"error": f"Port {port} is already in use"}
    if not ignore_network:
        try:
            net = ipaddress.ip_network(network)
        except ValueError:
            return False, {"error": f"Invalid network: {network}"}

        if not ignore_range_check:
            used_ranges = get_used_ip_ranges()

            for range in used_ranges:
                if net.overlaps(range):
                    return False, {
                        "error": f"Network {network} overlaps with existing range: {range}"
                    }

    return True, {"success": True}


def init_server(
    interface: str = None,
    port: int = None,
    network: str = None,
    public_ip: str | None = None,
    ignore_range_check: bool = True,
):
    """Initialize server state for an interface (idempotent).

    Args:
        interface: WireGuard interface name (auto-generated if None)
        port: Port number for WireGuard (auto-selected if None)
        network: Network CIDR for the VPN (auto-selected if None)
        public_ip: Public IP address for endpoint (auto-detected if None)
        ignore_range_check: If True, skip checking for network range overlaps

    Raises:
        SystemExit: If validation fails or interface name is invalid

    Note:
        Creates keypairs, assigns server IP, saves configuration, and generates
        WireGuard config file. Uses sensible defaults for all parameters.
    """
    ensure_root()
    ensure_directories()

    def_name, def_port, def_network, def_public_ip = get_new_interface_defaults()
    if not interface:
        interface = def_name
    if not port:
        port = def_port
    if not network:
        network = def_network
    if not public_ip:
        public_ip = def_public_ip

    print("Trying to create with:")
    print(f"  Interface: {interface}")
    print(f"  Port: {port}")
    print(f"  Network: {network}")
    print(f"  Public IP: {public_ip}")

    ok, meta = validate_new_interface(
        interface, port, network, ignore_range_check=ignore_range_check
    )

    if not ok:
        print(f"Error: {meta['error']}")
        print(f"Failed to validate new interface, due to {meta['error']}")
        raise Exception(meta["error"])

    if not public_ip:
        public_ip = get_public_ip()

    if any(c.isspace() for c in interface):
        raise Exception("Invalid interface name")

    data = load_data(interface)

    print(f"Initializing interface '{interface}'...")
    priv, pub = generate_keypair()
    data["server"]["private_key"] = priv
    data["server"]["public_key"] = pub
    data["server"]["network"] = network
    data["server"]["port"] = port
    data["server"]["public_ip"] = public_ip
    net = ipaddress.ip_network(network)
    data["server"]["ip"] = net.hosts().__next__().exploded
    save_data(interface, data)
    print(f"Server initialized with IP: {data['server']['ip']}")

    generate_config(interface, data)


def get_script_path() -> str:
    """Get the absolute path to the current script.

    Returns:
        Absolute path to this Python script file
    """
    return SCRIPT_PATH


def stop_all_interfaces():
    """Stop all active WireGuard interfaces managed by PyGuard.

    Note:
        Iterates through all known interfaces and stops those that are currently active.
    """
    ensure_root()
    interfaces = list_interfaces()
    count = 0
    for iface in interfaces:
        if iface.get("active"):
            try:
                print(f"Stopping interface {iface.get('name')}...")
                stop_wireguard(iface.get("name"))
                count += 1
            except Exception as e:
                print(f"Failed to stop {iface.get('name')}: {e}")
    print(f"Total stopped interfaces: {count}")


def launch_enabled_interfaces():
    """Launch all interfaces that have launch_on_start enabled.

    Note:
        Iterates through all known interfaces and starts those with
        launch_on_start set to True in their configuration.
    """
    ensure_root()
    interfaces = list_interfaces()
    count = 0
    for iface in interfaces:
        if iface.get("launch_on_start"):
            try:
                print(f"Launching interface {iface.get('name')}...")
                start_wireguard(iface.get("name"))
                count += 1
            except Exception as e:
                print(f"Failed to launch {iface.get('name')}: {e}")
    print(f"Total launched interfaces: {count}")


def ensure_launcher_service():
    """Create the pyguard-launcher systemd service file.

    Note:
        This service is a oneshot that can start/stop WireGuard interfaces
        based on their saved configuration. It uses the current script path.
    """
    ensure_root()
    if not command_exists("systemctl"):
        print("systemctl not found, cannot create launcher service")
        return
    service_content = f"""[Unit]
Description=PyGuard WireGuard Launcher
After=network.target

[Service]
Type=oneshot
ExecStart={sys.executable} {get_script_path()} launchAll
ExecStop={sys.executable} {get_script_path()} stopAll
WorkingDirectory={os.path.dirname(get_script_path())}
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
"""

    with open("/etc/systemd/system/pyguard-launcher.service.tmp", "w") as f:
        f.write(service_content)

    os.replace(
        "/etc/systemd/system/pyguard-launcher.service.tmp",
        "/etc/systemd/system/pyguard-launcher.service",
    )

    os.chmod("/etc/systemd/system/pyguard-launcher.service", 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("Created pyguard-launcher.service")
    subprocess.run(["systemctl", "enable", "pyguard-launcher.service"], check=False)
    print("Enabled pyguard-launcher.service to start on boot")


def enable_service(interface: str):
    """Enable systemd service for the WireGuard interface.

    Args:
        interface: The WireGuard interface name

    Note:
        Creates a systemd oneshot service that can start/stop the interface.
        Requires systemctl to be available. Prints status messages.
    """
    ensure_root()
    data = load_data(interface)  # Ensure data exists
    data["launch_on_start"] = True
    save_data(interface, data)

    ensure_launcher_service()


def stop_wireguard(interface: str):
    """Stop a WireGuard interface.

    Args:
        interface: The WireGuard interface name to stop

    Raises:
        SystemExit: If the interface cannot be stopped
    """
    ensure_root()
    if not command_exists("wg-quick"):
        print("wg-quick not found (WireGuard required)")
        return
    if not is_interface_active(interface):
        return
    try:
        subprocess.run(["wg-quick", "down", interface], check=True)
        print(f"Stopped interface: {interface}")
    except subprocess.CalledProcessError as e:
        print(f"Error stopping: {e}")
        raise Exception(f"Failed stopping interface {interface}: {e}")


def disable_service(interface: str):
    """Disable and remove systemd service for the WireGuard interface.

    Args:
        interface: The WireGuard interface name

    Note:
        Stops, disables, and removes the systemd service file.
        Continues gracefully if systemctl is not available.
    """
    ensure_root()
    data = load_data(interface)  # Ensure data exists
    data["launch_on_start"] = False
    save_data(interface, data)


def get_used_ips(interface: str) -> list[str]:
    """Get list of IP addresses already in use by peers on an interface.

    Args:
        interface: The WireGuard interface name

    Returns:
        List of IP address strings currently assigned to peers
    """
    ensure_root()
    data = load_data(interface)
    used = [peer.get("ip") for peer in data["peers"].values()]
    failsafe_ip = (
        ipaddress.ip_network(data.get("server", {}).get("network"))
        .hosts()
        .__next__()
        .exploded
    )
    used.append(data.get("server", {}).get("ip", failsafe_ip))
    return used


def check_new_peer(
    interface: str,
    name: str,
    peer_ip: str = None,
    ignore_name: bool = False,
    ignore_ip: bool = False,
):
    """Validate parameters for adding a new peer.

    Args:
        interface: The WireGuard interface name
        name: Peer name to validate
        peer_ip: IP address to validate (optional)
        ignore_name: If True, skip peer name validation
        ignore_ip: If True, skip IP address validation

    Returns:
        Tuple of (success: bool, metadata: dict)
        metadata contains either {"success": True} or {"error": "error message"}
    """
    ensure_root()
    data = load_data(interface)
    if name.lower() == "server" and not ignore_name:
        print("Error: Peer name 'server' is reserved")
        return False, {"error": "Peer name 'server' is reserved"}
    elif name in data["peers"].keys() and not ignore_name:
        print(f"Peer '{name}' already exists")
        return False, {"error": "Peer already exists"}
    elif not is_ip(peer_ip) and not ignore_ip:
        print(f"Error: Invalid IP address '{peer_ip}'")
        return False, {"error": "Invalid IP address"}
    elif peer_ip in get_used_ips(interface) and not ignore_ip:
        print(f"Error: IP address '{peer_ip}' is already in use")
        return False, {"error": "IP address is already in use"}
    elif (
        not (
            ipaddress.ip_address(peer_ip)
            in ipaddress.ip_network(
                data.get("server", {}).get("network", "255.255.255.255/32")
            )
        )
        and not ignore_ip
    ):
        print(f"Error: IP address '{peer_ip}' is not in the server network")
        return False, {"error": "IP address is not in the server network"}
    return True, {"success": True}


def add_peer(interface: str, name: str, peer_ip: str = None, allowed_ips=None):
    """Add a new peer to the WireGuard interface.

    Args:
        interface: The WireGuard interface name
        name: Name for the new peer
        peer_ip: IP address for the peer (auto-assigned if None)
        allowed_ips: Allowed IPs for the peer (uses server network if None)

    Note:
        Generates new keypair for the peer, validates parameters, saves configuration,
        and regenerates WireGuard config. Returns early if validation fails.
    """
    ensure_root()
    data = load_data(interface)

    if peer_ip == None:
        peer_ip = get_next_ip(interface)
    elif not check_new_peer(interface, name, peer_ip)[0]:
        return

    priv, pub = generate_keypair()
    default_allowed = data.get("server", {}).get("network", "0.0.0.0/0")
    data["peers"][name] = {
        "private_key": priv,
        "public_key": pub,
        "ip": peer_ip,
        "allowed_ips": allowed_ips or default_allowed,
        "created_at": subprocess.check_output("date -u +%Y-%m-%dT%H:%M:%SZ", shell=True)
        .decode()
        .strip(),
    }
    save_data(interface, data)
    print(f"Added peer '{name}' with IP: {peer_ip}")
    generate_config(interface, data, non_critical_change=True)


def remove_peer(interface: str, name_or_index: str):
    """Remove a peer from the WireGuard interface.

    Args:
        interface: The WireGuard interface name
        name_or_index: Peer name or numeric index (1-based) to remove

    Returns:
        Tuple of (success: bool, message: str)

    Note:
        Accepts either peer name or 1-based index. Updates configuration
        and regenerates WireGuard config file after removal.
    """
    ensure_root()
    data = load_data(interface)
    if name_or_index.isdigit():
        idx = int(name_or_index)
        names = sorted(data["peers"].keys())
        if idx < 1 or idx > len(names):
            print(f"Error: Index out of range (1..{len(names)})")
            return False, f"Error: Index out of range (1..{len(names)})"
        target = names[idx - 1]
    else:
        target = name_or_index
    if target not in data["peers"]:
        print(f"Peer '{target}' does not exist")
        return False, f"Peer '{target}' does not exist"
    del data["peers"][target]
    save_data(interface, data)
    print(f"Removed peer '{target}'")
    generate_config(interface, data, non_critical_change=True)
    return True, "Success"


def rotate_peer_key(interface: str, name: str):
    """Regenerate keypair for a peer (updates private/public keys).

    Args:
        interface: The WireGuard interface name
        name: Name of the peer to rotate keys for

    Note:
        Generates new private and public keys for the specified peer.
        Updates configuration and regenerates WireGuard config file.
    """
    ensure_root()
    data = load_data(interface)
    if name not in data["peers"]:
        print(f"Peer '{name}' does not exist")
        return
    priv, pub = generate_keypair()
    data["peers"][name]["private_key"] = priv
    data["peers"][name]["public_key"] = pub
    save_data(interface, data)
    print(f"Rotated keys for peer '{name}'")
    generate_config(interface, data, non_critical_change=True)


def rename_peer(interface: str, old: str, new: str):
    """Rename a peer (preserves keys and settings).

    Args:
        interface: The WireGuard interface name
        old: Current name of the peer
        new: New name for the peer

    Note:
        Preserves all peer configuration while changing only the name.
        Validates that new name doesn't conflict with existing peers.
    """
    ensure_root()
    if old == new:
        print("Old and new names are identical")
        return
    data = load_data(interface)
    if old not in data["peers"]:
        print(f"Peer '{old}' does not exist")
        return
    if new in data["peers"] or new.lower() == "server":
        print(f"Target name '{new}' invalid or already exists")
        return
    data["peers"][new] = data["peers"].pop(old)
    save_data(interface, data)
    print(f"Renamed peer '{old}' -> '{new}'")
    generate_config(interface, data, non_critical_change=True)


def list_peers(interface: str, print_output: bool = False, as_json: bool = False):
    """List peers for an interface; returns names or detail list if JSON.

    Args:
        interface: The WireGuard interface name
        print_output: If True, print formatted output to stdout
        as_json: If True, return detailed peer data for JSON serialization

    Returns:
        List of peer names (if as_json=False) or list of detailed peer dicts (if as_json=True)
        Each detailed dict includes all peer configuration and metadata.
    """
    data = load_data(interface)
    peers = data.get("peers", {})
    names = sorted(peers.keys())
    result = []

    for name in names:
        p = peers.get(name, {}).copy()
        p["name"] = name
        result.append(p)

    if print_output:
        if not as_json:
            if not names:
                print("No peers configured")
            else:
                print(
                    f"{'#':<4} {'Name':<20} {'IP':<15} {'Allowed IPs':<20} {'Public Key':<45} {'Created At':<20}"
                )
                print("-" * 128)
                for i, name in enumerate(names, start=1):
                    peer = peers[name]
                    print(
                        f"{i:<4} {name:<20} {peer['ip']:<15} {peer['allowed_ips']:<20} {peer['public_key']:<45} {peer.get('created_at','N/A'):<20}"
                    )
        else:
            print(json.dumps({"peers": result}, indent=2))
    return result


def build_server_config_string(data: dict) -> str:
    """Build the full server WireGuard configuration content as a string.

    Args:
        data: Interface configuration data dictionary

    Returns:
        Complete WireGuard configuration file content as a string

    Note:
        - Uses nftables PostUp/PostDown tied to the interface and current server network
        - Emits per-peer AllowedIPs as <peer_ip>/32 for clarity
        - Includes both default nftables rules and any custom commands
    """
    interface = data["server"]["interface"]
    table_name = f"{interface}_nat"
    network_cidr = data["server"]["network"]

    # Base header
    config = f"""[Interface]
PrivateKey = {data['server']['private_key']}
Address = {data['server']['ip']}/{data['server']['network'].split('/')[1]}
ListenPort = {data['server']['port']}
"""

    # Default nft PostUp/PostDown (plus any custom hooks stored in JSON)

    default_post_up = [
        f"nft add table ip {table_name}",
    ]
    if data.get("allow_vpn_gateway", False):
        default_post_up.append(
            f"nft add chain ip {table_name} postrouting_chain {{ type nat hook postrouting priority srcnat \\; policy accept \\; }}"
        )
        default_post_up.append(
            f"nft add rule ip {table_name} postrouting_chain ip saddr {network_cidr} counter masquerade"
        )

    if data.get("forward_to_docker_bridge"):
        ip, _ = get_local_gateway()
        if not (os.getenv("PYGUARD_IN_DOCKER") == "1"):
            print("This is not running inside a Docker container.")

        default_post_up.insert(
            1,
            f"nft add chain ip {table_name} prerouting_chain {{ type nat hook prerouting priority 0 \\; policy accept \\; }}",
        )
        if data.get("dns_service", False):
            default_post_up.insert(
                3,
                f"nft add rule ip {table_name} prerouting_chain ip daddr {data['server']['ip']} ip protocol tcp tcp dport != 53 dnat to {ip}",
            )
            default_post_up.insert(
                3,
                f"nft add rule ip {table_name} prerouting_chain ip daddr {data['server']['ip']} ip protocol udp udp dport != 53 dnat to {ip}",
            )
        else:
            default_post_up.insert(
                3,
                f"nft add rule ip {table_name} prerouting_chain ip daddr {data['server']['ip']} ip protocol tcp dnat to {ip}",
            )
            default_post_up.insert(
                3,
                f"nft add rule ip {table_name} prerouting_chain ip daddr {data['server']['ip']} ip protocol udp dnat to {ip}",
            )

    default_post_down = [
        f"nft delete table ip {table_name}",
    ]
    post_up_cmds = default_post_up + data["server"].get("custom_post_up", [])
    post_down_cmds = default_post_down + data["server"].get("custom_post_down", [])

    for cmd in post_up_cmds:
        config += f"PostUp = {cmd}\n"
    for cmd in post_down_cmds:
        config += f"PostDown = {cmd}\n"
    config += "\n"

    # Peers (server view shows /32 per-peer)
    for name, peer in data["peers"].items():
        allowed_for_view = f"{peer['ip']}/32"
        config += f"""# Peer: {name}
[Peer]
PublicKey = {peer['public_key']}
AllowedIPs = {allowed_for_view}

"""

    return config


def is_interface_active(interface: str) -> bool:
    """Check if a WireGuard interface is currently active.

    Args:
        interface: The WireGuard interface name

    Returns:
        True if the interface is active, False otherwise

    Note:
        Uses 'wg show <interface>' to determine if interface is running.
        Returns False if command fails or interface doesn't exist.
    """
    try:
        # 'wg show <iface>' returns non-zero if interface is not present
        subprocess.run(
            ["wg", "show", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def prepare_reduced_config(interface: str) -> str:
    """Create a reduced WireGuard configuration for syncconf operations.

    Args:
        interface: The WireGuard interface name

    Returns:
        Path to the temporary reduced configuration file

    Raises:
        ValueError: If server private key is missing

    Note:
        Creates a minimal config with only essential peer information
        for use with 'wg syncconf'. File is created with .temp extension.
    """
    data = load_data(interface)
    reduced_conf_path = f"/etc/pyguard/{interface}-reduced.temp"
    os.makedirs(os.path.dirname(reduced_conf_path), exist_ok=True)

    if not data.get("server", {}).get("private_key"):
        raise ValueError("Server private key is missing in data.")

    reduced_string = ""

    reduced_string += f"""[Interface]
    ListenPort = {data.get('server', {}).get('port', 0)}
    PrivateKey = {data.get('server', {}).get('private_key', '')}

    """
    for peer_name in data.get("peers", {}):
        peer = data["peers"][peer_name]
        reduced_string += f"""[Peer]
PublicKey = {peer['public_key']}
AllowedIPs = {peer['ip']}/32

"""

    with open(reduced_conf_path, "w") as f:
        f.write(reduced_string)

    return reduced_conf_path


def restart_wg_interface(interface: str, non_critical_change: bool = False):
    """Restart a WireGuard interface with appropriate method based on change type.

    Args:
        interface: The WireGuard interface name
        non_critical_change: If True, use syncconf for minimal disruption.
                            If False, perform full restart with down/up cycle.

    Note:
        For non-critical changes (peer additions, etc.), uses 'wg syncconf'
        to apply changes without disrupting existing connections.
        For critical changes, performs full interface restart.
    """
    # If systemd has an active wg-quick@interface, restart it
    if non_critical_change:
        path = prepare_reduced_config(interface)
        subprocess.run(["wg", "syncconf", interface, path], check=True)
        os.remove(path)
    elif command_exists("systemctl") and False:
        res = subprocess.run(
            ["systemctl", "is-active", f"wg-quick@{interface}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if res.returncode == 0:
            subprocess.run(
                ["systemctl", "restart", f"wg-quick@{interface}"], check=True
            )
            print(f"Restarted wg-quick@{interface}")
            return
    else:
        subprocess.run(["wg-quick", "down", interface], check=True)
        subprocess.run(["wg-quick", "up", interface], check=True)
        print(f"Interface '{interface}' brought down and up")


def rename_interface(interface: str, new_name: str):
    """Rename a WireGuard interface.

    Args:
        interface: Current interface name
        new_name: New interface name

    Returns:
        True if successful, False if validation fails

    Note:
        Validates new name, deletes old interface, saves data with new name.
        Restarts interface if it was active before renaming.
    """
    ensure_root()
    data = load_data(interface)
    active = is_interface_active(interface)
    if new_name == interface:
        print("Error: New name is the same as the current name")
        return False
    ok, meta = validate_new_interface(
        new_name, 0, "", ignore_network=True, ignore_range_check=True, ignore_port=True
    )

    if not ok:
        print(f"Error: {meta['error']}")
        return False

    delete_interface(interface)
    save_data(new_name, data)
    print(f"Renamed interface '{interface}' to '{new_name}'")
    if active:
        restart_wg_interface(interface)
    return True


def generate_config(
    interface: str, data: dict | None = None, non_critical_change: bool = False
):
    """Generate WireGuard configuration file and restart interface if active.

    Args:
        interface: The WireGuard interface name
        data: Configuration data dictionary (loaded from disk if None)
        non_critical_change: If True, use minimal restart method

    Raises:
        SystemExit: If interface restart fails

    Note:
        Writes the complete WireGuard configuration to /etc/wireguard/<interface>.conf
        and restarts the interface if it's currently active.
    """
    ensure_root()
    if data is None:
        data = load_data(interface)
    cfg_path = f"{CONFIG_DIR}/{interface}.conf"
    cfg = build_server_config_string(data)
    with open(cfg_path, "w") as f:
        f.write(cfg)
    os.chmod(cfg_path, stat.S_IRUSR | stat.S_IWUSR)
    print(f"Generated WireGuard config: {cfg_path}")
    try:
        if is_interface_active(interface):
            restart_wg_interface(interface, non_critical_change)
            print(f"Restarted active interface '{interface}'")
    except subprocess.CalledProcessError as e:
        print(f"Error restarting interface '{interface}': {e}")
        raise Exception(f"Failed restarting interface {interface}: {e}")


def show_server_config(
    interface: str, as_json: bool = False, print_output: bool = True
):
    """Display or return the server WireGuard configuration.

    Args:
        interface: The WireGuard interface name
        as_json: If True, return structured data instead of config text
        print_output: If True, print the configuration to stdout

    Returns:
        Configuration text string (if as_json=False) or detailed dict (if as_json=True)

    Note:
        Shows the complete server-side WireGuard configuration including
        all peers with their /32 allowed IPs.
    """
    data = load_data(interface)
    cfg = build_server_config_string(data)
    if as_json:
        result = {
            "interface": interface,
            "server": data.get("server", {}),
            "peers": data.get("peers", {}),
            "config_text": cfg,
        }
        if print_output:
            print(json.dumps(result, indent=2))
        return result
    if print_output:
        print("\nServer configuration:")
        print("-" * 60)
        print(cfg)
        print("-" * 60)
    return cfg


def generate_peer_config(interface: str, name: str) -> str | None:
    """Generate client configuration for a specific peer.

    Args:
        interface: The WireGuard interface name
        name: Name of the peer to generate config for

    Returns:
        Complete client WireGuard configuration as string, or None if peer doesn't exist

    Note:
        Generates a client-side configuration with server public key, endpoint,
        and peer's private key. Uses server's public IP or placeholder if not set.
    """
    ensure_root()
    data = load_data(interface)
    if name not in data["peers"]:
        print(f"Peer '{name}' does not exist")
        return None
    peer = data["peers"][name]
    server = data["server"]

    if data.get("dns_service", False):
        dns_ip = server.get("ip")
    else:
        dns_ip = server.get("dns", "1.1.1.1")

    client_allowed_ips = peer.get("allowed_ips") or server["network"]
    endpoint_host = server.get("public_ip") or "<SERVER_PUBLIC_IP>"
    return f"""[Interface]
PrivateKey = {peer['private_key']}
Address = {peer['ip']}/{server['network'].split('/')[1]}
DNS = {dns_ip}

[Peer]
PublicKey = {server['public_key']}
Endpoint = {endpoint_host}:{server['port']}
AllowedIPs = {client_allowed_ips}
PersistentKeepalive = 25
"""


def save_client_config(name, config):
    """Save client configuration to a file.

    Args:
        name: Name of the peer (used for filename)
        config: WireGuard configuration content as string

    Note:
        Creates ./client_configs/ directory and saves the configuration
        as <name>.conf. Prints the saved file path.
    """
    client_dir = Path("./client_configs")
    client_dir.mkdir(exist_ok=True)

    config_path = client_dir / f"{name}.conf"

    with open(config_path, "w") as f:
        f.write(config)

    print(f"Saved client configuration to: {config_path}")


def get_used_ports():
    """Return a sorted list of currently used TCP/UDP ports.

    Returns:
        Sorted list of integers representing ports currently in use by the system

    Note:
        Scans all network connections (TCP/UDP, IPv4/IPv6) to find used ports.
        Includes both local and remote ports from active connections.
    """
    used_ports = set()

    # Iterate over all connections (TCP/UDP, IPv4/IPv6)
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port:
            used_ports.add(conn.laddr.port)
        if conn.raddr and conn.raddr.port:
            used_ports.add(conn.raddr.port)

    return sorted(used_ports)


def generate_qr_code(config: str, name: str | None = None):
    """Generate/display QR code using 'qrencode' CLI.

    Args:
        config: WireGuard configuration content to encode
        name: If provided, save PNG to ./client_configs/{name}_qr.png
              If None, render ANSI QR to terminal

    Returns:
        True if successful, False if qrencode is unavailable or fails

    Note:
        - If name is provided, saves PNG to ./client_configs/{name}_qr.png
        - Otherwise, renders ANSI QR to terminal for immediate scanning
        - Automatically attempts to install qrencode if missing
    """
    try:
        ensure_qrencode_installed()
    except Exception as e:
        print(f"Failed to ensure qrencode is installed: {e}")
        return False
    if not command_exists("qrencode"):
        print("QR code generation not available: 'qrencode' is not installed.")
        print(
            "Install it with your package manager (e.g., 'sudo apt-get install qrencode')."
        )
        return False

    try:
        if name:
            client_dir = Path("./client_configs")
            client_dir.mkdir(exist_ok=True)
            img_path = client_dir / f"{name}_qr.png"
            # Pipe config to qrencode to create a PNG
            proc = subprocess.run(
                ["qrencode", "-o", str(img_path), "-t", "PNG", "-l", "L"],
                input=config.encode("utf-8"),
                check=True,
            )
            print(f"QR code saved to: {img_path}")
        else:
            # Render to terminal as ANSI UTF8
            print("Scan this QR code with your device:")
            subprocess.run(
                ["qrencode", "-t", "ANSIUTF8"], input=config.encode("utf-8"), check=True
            )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error generating QR code via qrencode: {e}")
        return False


def validate_allowed_ips(interface: str, new_allowed_ips: str) -> bool:
    """Validate new allowed IPs against the existing interface configuration.

    Args:
        interface: The WireGuard interface name
        new_allowed_ips: CIDR network string to validate

    Returns:
        Tuple of (success: bool, metadata: dict) - Note: docstring says bool but code returns tuple

    Note:
        Ensures that the interface's network is a subnet of the proposed allowed IPs.
        This prevents configuration that would break routing.
    """
    # Validate the new allowed IPs against the existing configuration
    data = load_data(interface)

    if not data:
        return False, {"error": "Failed to load interface data"}

    try:
        new_allowed_ips = ipaddress.ip_network(new_allowed_ips, strict=False)
    except ValueError:
        print(f"Invalid IP network: {new_allowed_ips}")
        return False, {"error": f"Invalid IP network: {new_allowed_ips}"}

    interface_network_str = data.get("server", {}).get("network", {})
    interface_network = ipaddress.ip_network(interface_network_str, strict=False)

    if not interface_network.subnet_of(new_allowed_ips):
        print(
            f"The network subnet ({interface_network_str}) is not a subnet of {new_allowed_ips}"
        )
        return False, {
            "error": f"The network subnet ({interface_network_str}) is not a subnet of {new_allowed_ips}"
        }

    return True, {"success": True}


def show_peer_config(
    interface: str,
    name: str,
    save_config=False,
    qr_code=False,
    save_qr=False,
    as_json: bool = False,
    print_output: bool = False,
):
    """Display peer configuration with various output options.

    Args:
        interface: The WireGuard interface name
        name: Name of the peer
        save_config: If True, save config to ./client_configs/{name}.conf
        qr_code: If True, display QR code in terminal
        save_qr: If True, save QR code as PNG file
        as_json: If True, return structured data instead of printing config
        print_output: If True, print configuration to stdout

    Returns:
        Dictionary with peer configuration details and metadata, or None if peer not found

    Note:
        Combines static peer data with runtime information from WireGuard.
        Includes endpoint information, transfer statistics, and connection status.
    """
    config = generate_peer_config(interface, name)

    data = load_data(interface)
    peer = data.get("peers", {}).get(name)
    if peer is None:
        if print_output:
            print(json.dumps({"error": "peer_not_found", "peer": name}, indent=2))
        return None

    additional_peer_info = get_peers_info(interface, specific_peer=name)
    if additional_peer_info:
        peer.update(additional_peer_info)

    if not config:
        return None

    server = data.get("server", {})
    result = {
        "interface": interface,
        "peer": name,
        "peer_data": peer,
        "config_text": config,
        "server_public_key": server.get("public_key"),
        "server_endpoint_host": server.get("public_ip") or None,
        "server_port": server.get("port"),
        "server_network": server.get("network"),
        "server_dns": server.get("dns"),
        "needs_public_ip": not bool(server.get("public_ip")),
    }

    if print_output:
        if not as_json:
            placeholder = "<SERVER_PUBLIC_IP>" in config
            print(f"\nConfiguration for peer '{name}' (interface {interface}):")
            print("-" * 60)
            print(config)
            print("-" * 60)
            if placeholder:
                print(
                    "NOTE: Set a public endpoint: pyguard {interface} update public-ip <host>"
                )
        else:
            print(json.dumps(result, indent=2))
    if save_config:
        save_client_config(name, config)
    if qr_code or save_qr:
        if save_qr:
            generate_qr_code(config, name)
        else:
            generate_qr_code(config)

    return result


def start_wireguard(interface: str):
    """Start a WireGuard interface.

    Args:
        interface: The WireGuard interface name to start

    Raises:
        SystemExit: If the interface cannot be started

    Note:
        Generates configuration and starts the interface using wg-quick.
        Ensures the latest configuration is applied before starting.
    """
    if is_interface_active(interface):
        print(f"Interface '{interface}' is already active")
        return
    ensure_root()
    data = load_data(interface)
    generate_config(interface, data)
    try:
        subprocess.run(["wg-quick", "up", interface], check=True)
        print(f"Started interface: {interface}")
    except subprocess.CalledProcessError as e:
        print(f"Error starting: {e}")
        raise Exception(f"Failed starting interface {interface}: {e}")


def add_custom_command(interface: str, direction: str, command: str):
    """Add a custom PostUp or PostDown command to the interface.

    Args:
        interface: The WireGuard interface name
        direction: Either "up" (PostUp) or "down" (PostDown)
        command: Shell command to add

    Note:
        Commands are executed when the interface starts (PostUp) or stops (PostDown).
        Regenerates the WireGuard configuration after adding the command.
    """
    ensure_root()
    data = load_data(interface)
    key = "custom_post_up" if direction == "up" else "custom_post_down"
    data["server"][key].append(command)
    save_data(interface, data)
    print(f"Added custom {direction} command: {command}")
    # Custom hook impacts server config -> regenerate
    generate_config(interface, data)


def list_custom_commands(interface: str, direction: str):
    """List custom PostUp or PostDown commands for an interface.

    Args:
        interface: The WireGuard interface name
        direction: Either "up" (PostUp) or "down" (PostDown)

    Note:
        Prints numbered list of custom commands or message if none exist.
    """
    data = load_data(interface)
    key = "custom_post_up" if direction == "up" else "custom_post_down"
    cmds = data["server"].get(key, [])
    if not cmds:
        print(f"No custom {direction} commands")
        return
    for i, cmd in enumerate(cmds, start=1):
        print(f"{i}. {cmd}")


def delete_custom_command(interface: str, direction: str, identifier: str):
    """Delete a custom PostUp or PostDown command.

    Args:
        interface: The WireGuard interface name
        direction: Either "up" (PostUp) or "down" (PostDown)
        identifier: Either numeric index (1-based) or exact command string

    Note:
        Can delete by index number or by matching the exact command text.
        Regenerates WireGuard configuration after deletion.
    """
    ensure_root()
    data = load_data(interface)
    key = "custom_post_up" if direction == "up" else "custom_post_down"
    cmds = data["server"].get(key, [])
    if not cmds:
        print(f"No custom {direction} commands")
        return
    removed = None
    if identifier.isdigit():
        idx = int(identifier) - 1
        if 0 <= idx < len(cmds):
            removed = cmds.pop(idx)
    else:
        try:
            cmds.remove(identifier)
            removed = identifier
        except ValueError:
            pass
    if removed is None:
        print(f"Not found: {identifier}")
        return
    data["server"][key] = cmds
    save_data(interface, data)
    print(f"Deleted custom {direction} command: {removed}")
    # Hooks changed -> regenerate config
    generate_config(interface, data)


def show_status(interface: str):
    """Show WireGuard interface status.

    Args:
        interface: The WireGuard interface name

    Raises:
        SystemExit: If status command fails

    Note:
        Runs 'wg show <interface>' to display current interface status
        including peer connections, handshakes, and transfer statistics.
    """
    ensure_root()
    subprocess.run(["wg", "show", interface], check=False)


def update_config(interface: str, target: str, parameter: str, value: str):
    """Update configuration parameters for server or peer.

    Args:
        interface: The WireGuard interface name
        target: Either server parameter name or peer name
        parameter: Parameter to update (varies by target type)
        value: New value for the parameter

    Note:
        Server parameters: port, dns, public-ip, network
        Peer parameters: allowed-ips, rename, rotate-keys, ip

        For server updates, regenerates full configuration.
        For peer updates, uses minimal restart when possible.
    """
    ensure_root()
    data = load_data(interface)
    if target == "port":
        try:
            p = int(value)
            if 1 <= p <= 65535:
                data["server"]["port"] = p
                save_data(interface, data)
                print(f"Port updated: {p}")
                generate_config(interface, data)
            else:
                print("Port must be 1..65535")
        except ValueError:
            print("Port must be numeric")
        return
    if target == "dns":
        data["server"]["dns"] = value
        save_data(interface, data)
        print(f"DNS updated: {value}")
        generate_config(interface, data)
        return
    if target in ("public-ip", "host", "endpoint-host"):
        data["server"]["public_ip"] = value
        save_data(interface, data)
        print(f"Public endpoint set: {value}")
        # generate_config(interface, data)
        return
    if target == "dns_service":
        if value.lower() in ("1", "true", "yes", "on", "enable", "enabled"):
            data["dns_service"] = True
            print("DNS service enabled (peer configs will use server IP as DNS)")
        else:
            data["dns_service"] = False
            print("DNS service disabled (peer configs will use custom DNS)")
        save_data(interface, data)
        generate_config(interface, data, non_critical_change=True)
        return
    if target == "forward_to_docker_bridge":
        if value.lower() in ("1", "true", "yes", "on", "enable", "enabled"):
            data["forward_to_docker_bridge"] = True
            print("Forwarding to Docker bridge enabled")
        else:
            data["forward_to_docker_bridge"] = False
            print("Forwarding to Docker bridge disabled")
        save_data(interface, data)
        generate_config(interface, data)
        return
    if target == "allow_vpn_gateway":
        if value.lower() in ("1", "true", "yes", "on", "enable", "enabled"):
            data["allow_vpn_gateway"] = True
            print("VPN gateway (NAT) enabled")
        else:
            data["allow_vpn_gateway"] = False
            print("VPN gateway (NAT) disabled")
        save_data(interface, data)
        generate_config(interface, data)
        return

    # Regenerate for consistency (even if public_ip not used in server config yet)
    # generate_config(interface, data)
    # return
    if target == "network":
        try:
            new_net = ipaddress.ip_network(value)
            data["server"]["network"] = value
            data["server"]["ip"] = new_net.hosts().__next__().exploded
            try:
                current_ip = ipaddress.ip_address(data["server"].get("ip", "0.0.0.0"))
                if current_ip not in new_net:
                    data["server"]["ip"] = str(next(new_net.hosts()))
                    print(f"Server IP moved to {data['server']['ip']}")
            except ValueError:
                data["server"]["ip"] = str(next(new_net.hosts()))
                print(f"Server IP set to {data['server']['ip']}")

            for peer_name in data.get("peers", {}).keys():
                peer = data.get("peers", {}).get(peer_name, {})
                if ipaddress.ip_address(peer["ip"]) not in new_net:
                    peer["ip"] = get_next_ip(interface, value)
                    print(f"Peer {peer_name} IP moved to {peer['ip']}")

            save_data(interface, data)
            print(f"Network updated: {value}")
            generate_config(interface, data)
        except ValueError as e:
            print(f"Invalid network: {e}")
        return
    # Peer update
    if target not in data["peers"]:
        print(f"Peer '{target}' not found")
        return
    peer_obj = data["peers"][target]
    if parameter == "allowed-ips":
        peer_obj["allowed_ips"] = value
        save_data(interface, data)
        print(f"Updated allowed-ips for {target} -> {value}")
        generate_config(interface, data, non_critical_change=True)
        return
    if parameter in ("rename", "name"):
        if not value:
            print("New name required")
            return
        if value in data["peers"] or value.lower() == "server":
            print(f"Target name '{value}' invalid or already exists")
            return
        data["peers"][value] = data["peers"].pop(target)

        save_data(interface, data)
        print(f"Peer renamed: {target} -> {value}")
        generate_config(interface, data, non_critical_change=True)
        return
    if parameter in ("rotate-keys", "rotate", "regen-keys"):
        # Regenerate peer keypair
        priv, pub = generate_keypair()
        peer_obj["private_key"] = priv
        peer_obj["public_key"] = pub
        save_data(interface, data)
        print(f"Rotated keys for peer '{target}'")
        generate_config(interface, data, non_critical_change=True)
        return
    if parameter == "ip":
        try:
            new_ip = ipaddress.ip_address(value)
        except ValueError:
            print(f"Invalid IP: {value}")
            return
        # Ensure within server network
        net = ipaddress.ip_network(data["server"]["network"])
        if new_ip not in net:
            print(f"IP {new_ip} not in network {net}")
            return
        # Ensure not used by server or other peers
        taken = {p["ip"] for n, p in data["peers"].items() if n != target}
        taken.add(data["server"].get("ip", ""))
        if str(new_ip) in taken:
            print(f"IP {new_ip} already in use")
            return
        old_ip = peer_obj["ip"]
        peer_obj["ip"] = str(new_ip)
        save_data(interface, data)
        print(f"Peer {target} IP changed {old_ip} -> {new_ip}")
        generate_config(interface, data, non_critical_change=True)
        return
    print(
        f"Unknown peer parameter '{parameter}' (supported: allowed-ips, rename, rotate-keys, ip)"
    )


def help():
    """Display comprehensive help information for PyGuard CLI.

    Shows usage patterns, command descriptions, and examples for all
    available PyGuard commands including interface management,
    peer operations, and configuration updates.
    """
    txt = """
PyGuard - WireGuard VPN Manager (interface-first CLI)

Usage:
  pyguard help|--help|-h
      Show this help.

  pyguard list [--json]
      List interfaces managed by PyGuard.

  pyguard init [<iface>] [--port N] [--network CIDR] [--public-ip HOST]
      Initialize server config. Sensible defaults are auto-selected (free name/port/network).

  pyguard <iface> start|stop|status
      Manage WireGuard interface via wg-quick.

  pyguard <iface> enable|disable
      Enable/disable systemd oneshot service pyguard-<iface>.service.

  pyguard <iface> add <peer> [<ip>]
  pyguard <iface> remove <peer|index>
  pyguard <iface> list [--json]
      Manage or list peers for an interface.

  pyguard <iface> show server [--json]
  pyguard <iface> show <peer> [--save|--qr|--save-qr|--json]
      Show server or peer/client configuration.

  pyguard <iface> update port <N>
  pyguard <iface> update dns <IP>
  pyguard <iface> update public-ip <HOST|IP>
  pyguard <iface> update network <CIDR>
  pyguard <iface> rename <NEW_NAME>
  pyguard <iface> update <peer> allowed-ips <CIDR>
  pyguard <iface> update <peer> rename <NEW_NAME>
  pyguard <iface> update <peer> rotate-keys
  pyguard <iface> update <peer> ip <NEW_IP>
      Update server or peer settings.


  pyguard <iface> custom add up|down <cmd>
  pyguard <iface> custom list up|down
  pyguard <iface> custom delete up|down <index|command>
      Manage PostUp / PostDown hook commands.

  pyguard <iface> delete interface
      Remove state, generated config, and service for <iface>.

Notes:
  - State files: /etc/pyguard/<iface>.conf (JSON)
  - WireGuard configs: /etc/wireguard/<iface>.conf
  - Client QR/PNG output requires 'qrencode' to be installed.
  - If public endpoint isn't set, client configs include <SERVER_PUBLIC_IP> placeholder.
  - Server IP defaults to the first host in the configured network.
""".strip()
    print(txt)


def main():
    """Main entry point for the PyGuard CLI application.

    Parses command line arguments and routes to appropriate functions.
    Handles both top-level commands (help, list, init, delete) and
    interface-specific commands (start, stop, add, remove, etc.).

    Command structure:
        - Top-level: pyguard <command> [args...]
        - Interface-specific: pyguard <interface> <command> [args...]

    Raises:
        SystemExit: On command errors or exceptions
    """
    if len(sys.argv) < 2:
        help()
        return

    if sys.argv[1] == "debug":
        print(get_peers_info("semiqa"))
        exit(0)
    # Top-level commands without interface
    if sys.argv[1] in ("help", "--help", "-h"):
        help()
        return
    if sys.argv[1] == "launchAll":
        launch_enabled_interfaces()
        return
    if sys.argv[1] == "stopAll":
        stop_all_interfaces()
        return
    if sys.argv[1] == "list":
        json_mode = "--json" in sys.argv[2:]
        list_interfaces(as_json=json_mode, print_output=True)
        return
    # New preferred top-level init form: pyguard init <iface> [flags]
    if sys.argv[1] == "init":
        if len(sys.argv) < 2:
            print(
                "Usage: pyguard init [<iface>] [--port N] [--network CIDR] [--public-ip HOST]"
            )
            return
        args = sys.argv[2:]
        interface = port = net = pub = None
        i = 0
        while i < len(args):
            if i == 0:
                interface = args[i]
            a = args[i]
            if a in ("--port", "-p") and i + 1 < len(args):
                port = args[i + 1]
                i += 2
                continue
            if a in ("--network", "-n") and i + 1 < len(args):
                net = args[i + 1]
                i += 2
                continue
            if a in ("--public-ip", "-H", "-host", "-h") and i + 1 < len(args):
                pub = args[i + 1]
                i += 2
                continue
            i += 1
        init_server(interface, port=port, network=net, public_ip=pub)
        return
    elif sys.argv[1] == "delete":
        to_delete = sys.argv[2:]
        for interface in to_delete:
            try:
                delete_interface(interface)
            except Exception as e:
                print(f"Error deleting interface {interface}: {e}")
            print("-" * 40)
        print("Done!")
        return

    # Interface-first flow
    interface = sys.argv[1]
    if len(sys.argv) == 2:
        help()
        return
    command = sys.argv[2]
    args = sys.argv[3:]
    try:
        if command == "start":
            start_wireguard(interface)
        elif command == "stop":
            stop_wireguard(interface)
        elif command == "status":
            show_status(interface)
        elif command == "enable":
            enable_service(interface)
        elif command == "disable":
            disable_service(interface)
        elif command == "add":
            if not args:
                print("Usage: pyguard <iface> add <peer> [<ip>]")
                return
            add_peer(interface, args[0], args[1] if len(args) > 1 else None)
        elif command == "remove":
            if not args:
                print("Usage: pyguard <iface> remove <peer|index>")
                return
            remove_peer(interface, args[0])
        elif command == "list":
            json_mode = "--json" in args
            list_peers(interface, as_json=json_mode, print_output=True)
        elif command == "show":
            if not args:
                print(
                    "Usage: pyguard <iface> show <server|peer> [--save|--qr|--save-qr|--json]"
                )
                return
            name = args[0]
            flags = args[1:]
            save_conf = "--save" in flags
            qr = "--qr" in flags
            save_qr = "--save-qr" in flags
            json_mode = "--json" in flags
            if name.lower() == "server":
                show_server_config(interface, as_json=json_mode, print_output=True)
            else:
                show_peer_config(
                    interface,
                    name,
                    save_conf,
                    qr,
                    save_qr,
                    as_json=json_mode,
                    print_output=True,
                )
        elif command == "rename":
            if not args:
                print("Usage: pyguard <iface> rename <new_name>")
                return
            new_name = args[0]
            rename_interface(interface, new_name)
        elif command == "dns_service":
            if not args:
                print("Usage: pyguard <iface> dns_service <enable|disable>")
                return
            val = args[0]
            if val.lower() in ("1", "true", "yes", "on", "enable", "enabled"):
                update_config(interface, "dns_service", "dns_service", "enable")
            else:
                update_config(interface, "dns_service", "dns_service", "disable")

        elif command == "custom":
            if len(args) < 2:
                print(
                    "Usage: pyguard <iface> custom <add|list|delete> <up|down> [cmd|index]"
                )
                return
            action = args[0]
            direction = args[1]
            if direction not in ("up", "down"):
                print("Direction must be up|down")
                return
            if action == "add":
                if len(args) < 3:
                    print("Usage: pyguard <iface> custom add <up|down> <command>")
                    return
                cmd = " ".join(args[2:])
                add_custom_command(interface, direction, cmd)
            elif action == "list":
                list_custom_commands(interface, direction)
            elif action == "delete":
                if len(args) < 3:
                    print(
                        "Usage: pyguard <iface> custom delete <up|down> <index|command>"
                    )
                    return
                ident = " ".join(args[2:])
                delete_custom_command(interface, direction, ident)
            else:
                print("Unknown custom action")
        elif command == "update":
            if len(args) < 2:
                print(
                    "Usage: pyguard <iface> update <server-param> <value> | update <peer> <param> <value>|rotate-keys"
                )
                return
            # Peer rotate-keys form: update <peer> rotate-keys
            if len(args) == 2 and args[1] in ("rotate-keys", "rotate", "regen-keys"):
                target, param = args
                update_config(interface, target, param, "")
            elif len(args) == 2:  # server param
                target, value = args
                update_config(interface, target, target, value)
            else:  # peer param requiring value
                target, param = args[0], args[1]
                if param in ("rotate-keys", "rotate", "regen-keys"):
                    update_config(interface, target, param, "")
                else:
                    if len(args) < 3:
                        print("Missing value for peer parameter")
                        return
                    value = args[2]
                    update_config(interface, target, param, value)
        elif command == "delete" and args and args[0] == "interface":
            delete_interface(interface)
        elif command == "help":
            help()
        else:
            print(f"Unknown command: {command}")
            help()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
