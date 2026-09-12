"""
Port Scanner Collector for DomainAtlas OSINT Pipeline

Performs TCP port scanning on discovered IP addresses
with service detection and optional banner grabbing.
"""

import socket
import re
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Callable


# =============================================================
# COMMON TCP PORTS
# =============================================================

COMMON_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MongoDB",
}


# Web ports that need HTTP probes
HTTP_PORTS = {80, 443, 8080, 8443}


# =============================================================
# CANCELLATION HELPER
# =============================================================

def is_cancelled(
    cancellation_callback: Optional[Callable[[], bool]]
) -> bool:
    """Safely check whether the current scan has been cancelled."""

    if cancellation_callback is None:
        return False

    try:
        return bool(cancellation_callback())
    except Exception:
        return False


# =============================================================
# SERVICE BANNER GRABBING
# =============================================================

def grab_banner(
    ip: str,
    port: int,
    timeout: float = 2.0
) -> Optional[str]:
    """
    Attempt to grab a service banner from an open TCP port.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.settimeout(timeout)

        # Connect to the already confirmed open port
        sock.connect((ip, port))

        # -----------------------------------------------------
        # Protocol-specific probes
        # -----------------------------------------------------

        if port in HTTP_PORTS:
            sock.sendall(
                b"HEAD / HTTP/1.0\r\n"
                b"Host: localhost\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )

        elif port == 25:
            sock.sendall(b"EHLO test\r\n")

        elif port == 110:
            sock.sendall(b"QUIT\r\n")

        elif port == 143:
            sock.sendall(b"A001 CAPABILITY\r\n")

        elif port == 6379:
            sock.sendall(b"PING\r\n")

        # SSH, FTP, etc. often send a banner immediately.

        # -----------------------------------------------------
        # Receive response
        # -----------------------------------------------------

        try:
            data = sock.recv(4096)
        except socket.timeout:
            return None

        if not data:
            return None

        banner = data.decode(
            "utf-8",
            errors="ignore"
        ).strip()

        # Clean banner
        banner = re.sub(r"[\r\n]+", " ", banner)
        banner = re.sub(r"\s+", " ", banner).strip()

        if len(banner) > 255:
            banner = banner[:252] + "..."

        return banner if banner else None

    except (
        socket.timeout,
        socket.error,
        OSError,
        UnicodeDecodeError
    ):
        return None

    finally:
        try:
            sock.close()
        except Exception:
            pass


# =============================================================
# REFINE SERVICE FROM BANNER
# =============================================================

def refine_service_from_banner(
    banner: Optional[str],
    port: int
) -> str:
    """
    Attempt to identify a service more precisely from its banner.
    """

    if not banner:
        return COMMON_PORTS.get(port, "unknown")

    banner_lower = banner.lower()

    # ---------------------------------------------------------
    # Web servers
    # ---------------------------------------------------------

    if "apache" in banner_lower:
        return "HTTP (Apache)"

    if "nginx" in banner_lower:
        return "HTTP (nginx)"

    if "microsoft-iis" in banner_lower:
        return "HTTP (IIS)"

    if "caddy" in banner_lower:
        return "HTTP (Caddy)"

    if "cloudflare" in banner_lower:
        return "HTTP (Cloudflare)"

    # ---------------------------------------------------------
    # SSH
    # ---------------------------------------------------------

    if "openssh" in banner_lower:
        return "SSH (OpenSSH)"

    if "dropbear" in banner_lower:
        return "SSH (Dropbear)"

    # ---------------------------------------------------------
    # FTP
    # ---------------------------------------------------------

    if "vsftpd" in banner_lower:
        return "FTP (vsftpd)"

    if "proftpd" in banner_lower:
        return "FTP (ProFTPD)"

    if "pure-ftpd" in banner_lower:
        return "FTP (Pure-FTPd)"

    # ---------------------------------------------------------
    # Mail
    # ---------------------------------------------------------

    if "postfix" in banner_lower:
        return "SMTP (Postfix)"

    if "sendmail" in banner_lower:
        return "SMTP (Sendmail)"

    if "exim" in banner_lower:
        return "SMTP (Exim)"

    if "dovecot" in banner_lower:
        return "IMAP/POP3 (Dovecot)"

    # ---------------------------------------------------------
    # Databases
    # ---------------------------------------------------------

    if "mysql" in banner_lower:
        return "MySQL"

    if "postgres" in banner_lower:
        return "PostgreSQL"

    if "mongodb" in banner_lower:
        return "MongoDB"

    if "redis" in banner_lower:
        return "Redis"

    return COMMON_PORTS.get(port, "unknown")


# =============================================================
# SCAN SINGLE PORT
# =============================================================

def scan_single_port(
    ip: str,
    port: int,
    timeout: float = 1.0,
    enable_banner_grabbing: bool = True
) -> Dict[str, Any]:
    """
    Scan one TCP port.

    Returns:
        {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "HTTP",
            "banner": "...",
            "banner_available": True
        }
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.settimeout(timeout)

        # -----------------------------------------------------
        # TCP connection test
        # -----------------------------------------------------

        result = sock.connect_ex((ip, port))

        if result != 0:
            return {
                "port": port,
                "protocol": "tcp",
                "state": "closed",
                "service": "unknown",
                "banner": None,
                "banner_available": False
            }

    except (
        socket.timeout,
        socket.error,
        OSError
    ):
        return {
            "port": port,
            "protocol": "tcp",
            "state": "closed",
            "service": "unknown",
            "banner": None,
            "banner_available": False
        }

    finally:
        try:
            sock.close()
        except Exception:
            pass

    # =========================================================
    # PORT IS OPEN
    # =========================================================

    banner = None
    service = COMMON_PORTS.get(port, "unknown")

    # ---------------------------------------------------------
    # Banner grabbing
    # ---------------------------------------------------------

    if enable_banner_grabbing:
        banner = grab_banner(
            ip,
            port,
            timeout=timeout * 2
        )

        if banner:
            service = refine_service_from_banner(
                banner,
                port
            )

    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "service": service,
        "banner": banner,
        "banner_available": banner is not None
    }


# =============================================================
# SCAN IP ADDRESS
# =============================================================

def scan_ip(
    ip: str,
    ports: Optional[Dict[int, str]] = None,
    timeout: float = 1.0,
    max_workers: int = 50,
    enable_banner_grabbing: bool = True,
    cancellation_callback: Optional[Callable[[], bool]] = None
) -> Dict[str, Any]:
    """
    Scan all configured TCP ports on one IP address.
    """

    if ports is None:
        ports = COMMON_PORTS

    open_ports = []

    start_time = time.time()

    # ---------------------------------------------------------
    # Concurrent port scanning
    # ---------------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        future_to_port = {
            executor.submit(
                scan_single_port,
                ip,
                port,
                timeout,
                enable_banner_grabbing
            ): port
            for port in ports.keys()
        }

        for future in as_completed(future_to_port):

            # Cancellation
            if is_cancelled(cancellation_callback):

                for f in future_to_port:
                    f.cancel()

                break

            try:
                result = future.result()

                if result["state"] == "open":
                    open_ports.append(result)

            except Exception as exc:
                print(
                    f"[Port Scan] Error scanning "
                    f"{ip}:{future_to_port[future]}: {exc}"
                )

    scan_time = time.time() - start_time

    # Sort ports numerically
    open_ports.sort(
        key=lambda item: item["port"]
    )

    return {
        "ip": ip,
        "scan_time": round(scan_time, 2),
        "open_ports": open_ports,
        "open_count": len(open_ports)
    }


# =============================================================
# SCAN MULTIPLE IP ADDRESSES
# =============================================================

def scan_ips(
    ips: List[str],
    ports: Optional[Dict[int, str]] = None,
    timeout: float = 1.0,
    max_workers_per_ip: int = 50,
    max_concurrent_ips: int = 10,
    enable_banner_grabbing: bool = True,
    cancellation_callback: Optional[Callable[[], bool]] = None,
    progress_callback: Optional[Callable[[Dict], None]] = None
) -> List[Dict[str, Any]]:
    """
    Scan multiple IP addresses.
    """

    if not ips:
        return []

    if ports is None:
        ports = COMMON_PORTS

    # Deduplicate IP addresses
    unique_ips = list(dict.fromkeys(ips))

    results = []

    total_ips = len(unique_ips)

    # ---------------------------------------------------------
    # Scan IPs
    # ---------------------------------------------------------

    for idx, ip in enumerate(unique_ips, 1):

        if is_cancelled(cancellation_callback):
            break

        print(
            f"[Port Scan] Scanning "
            f"{ip} ({idx}/{total_ips})..."
        )

        ip_result = scan_ip(
            ip=ip,
            ports=ports,
            timeout=timeout,
            max_workers=max_workers_per_ip,
            enable_banner_grabbing=enable_banner_grabbing,
            cancellation_callback=cancellation_callback
        )

        # Only keep IPs with open ports
        if ip_result["open_count"] > 0:

            results.append(ip_result)

            print(
                f"[Port Scan] {ip}: "
                f"{ip_result['open_count']} open port(s)"
            )

            for port in ip_result["open_ports"]:
                print(
                    f"    {port['port']}/tcp "
                    f"→ {port['service']}"
                )

                if port["banner"]:
                    print(
                        f"       Banner: "
                        f"{port['banner']}"
                    )

        else:
            print(
                f"[Port Scan] {ip}: "
                f"no open common ports"
            )

        # Progress callback
        if progress_callback:

            try:
                progress_callback({
                    "current": idx,
                    "total": total_ips,
                    "ip": ip,
                    "open_ports": ip_result["open_count"]
                })

            except Exception:
                pass

    return results


# =============================================================
# COLLECTOR INTERFACE FOR OSINT PIPELINE
# =============================================================

def collect_port_scan_data(
    ips: List[str],
    ports: Optional[Dict[int, str]] = None,
    timeout: float = 1.0,
    enable_banner_grabbing: bool = True,
    cancellation_callback: Optional[Callable[[], bool]] = None,
    progress_callback: Optional[Callable[[Dict], None]] = None
) -> Dict[str, Any]:
    """
    Collector interface for the DomainAtlas OSINT pipeline.
    """

    if not ips:

        return {
            "port_scan": {
                "scanned_ips": 0,
                "open_ports_total": 0,
                "results": []
            }
        }

    results = scan_ips(
        ips=ips,
        ports=ports,
        timeout=timeout,
        enable_banner_grabbing=enable_banner_grabbing,
        cancellation_callback=cancellation_callback,
        progress_callback=progress_callback
    )

    total_open = sum(
        result["open_count"]
        for result in results
    )

    return {
        "port_scan": {
            "scanned_ips": len(ips),
            "open_ports_total": total_open,
            "results": results
        }
    }


# =============================================================
# STANDALONE TEST
# =============================================================

if __name__ == "__main__":

    # Authorized Nmap test target
    test_ips = ["45.33.32.156"]

    print("Testing port scanner...")
    print("-" * 50)

    results = collect_port_scan_data(
        test_ips,
        timeout=2.0,
        enable_banner_grabbing=True
    )

    port_scan = results["port_scan"]

    print("-" * 50)
    print(
        f"Scanned IPs: "
        f"{port_scan['scanned_ips']}"
    )

    print(
        f"Open ports total: "
        f"{port_scan['open_ports_total']}"
    )

    for ip_result in port_scan["results"]:

        print(
            f"\nIP: "
            f"{ip_result['ip']}"
        )

        print(
            f"Scan time: "
            f"{ip_result['scan_time']}s"
        )

        print(
            f"Open ports: "
            f"{ip_result['open_count']}"
        )

        for port in ip_result["open_ports"]:

            print(
                f"  Port "
                f"{port['port']}/tcp: "
                f"{port['service']}"
            )

            if port["banner"]:

                print(
                    f"    Banner: "
                    f"{port['banner']}"
                )