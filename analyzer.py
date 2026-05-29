import asyncio
import socket
import ssl

DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
UNSECURE_CIPHER_KEYWORDS = ["RC4", "DES", "MD5", "NULL", "EXPORT", "RC2"]

async def check_protocol_and_tls(ip, port, timeout=2):
    loop = asyncio.get_running_loop()

    # Try SSL first
    def try_ssl():
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # We need to allow older protocols to check if they are supported
        try:
            context.options &= ~ssl.OP_NO_TLSv1
            context.options &= ~ssl.OP_NO_TLSv1_1
        except Exception:
            pass

        try:
            # Setting up a connection
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    return "HTTPS", version, cipher
        except Exception as e:
            return None, None, None

    result = await loop.run_in_executor(None, try_ssl)
    if result[0] == "HTTPS":
        return result

    # Try HTTP
    def try_http():
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                # Send a simple HTTP request
                sock.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                data = sock.recv(1024)
                if b"HTTP/" in data:
                    return "HTTP", None, None
        except Exception:
            pass
        return "Other", None, None

    result = await loop.run_in_executor(None, try_http)
    return result

def is_cipher_unsecure(cipher_name):
    if not cipher_name:
        return False
    return any(keyword in cipher_name.upper() for keyword in UNSECURE_CIPHER_KEYWORDS)

async def analyze_ports_async(scan_results, timeout=2):
    """
    Takes the output of scan_ports and checks the protocol and TLS status of open ports.
    """
    tasks = []

    # Create a mapping of task to (ip, port)
    task_mapping = {}

    for result in scan_results:
        ip = result["ip"]
        for port in result["open_ports"]:
            task = asyncio.create_task(check_protocol_and_tls(ip, port, timeout))
            tasks.append(task)
            task_mapping[task] = (ip, port)

    if not tasks:
        return []

    await asyncio.gather(*tasks)

    enriched_results = []

    # Group back by IP
    ip_to_data = {}
    for result in scan_results:
        ip_to_data[result["ip"]] = []

    for task in tasks:
        ip, port = task_mapping[task]
        protocol, tls_version, cipher_tuple = task.result()

        port_data = {
            "port": port,
            "protocol": protocol
        }

        if protocol == "HTTPS":
            port_data["tls_version"] = tls_version
            if cipher_tuple:
                cipher_name = cipher_tuple[0]
                port_data["cipher"] = cipher_name

                warnings = []
                if tls_version in DEPRECATED_TLS_VERSIONS:
                    warnings.append(f"Deprecated TLS version detected: {tls_version}")
                if is_cipher_unsecure(cipher_name):
                    warnings.append(f"Unsecure cipher detected: {cipher_name}")

                if warnings:
                    port_data["security_warnings"] = warnings

        ip_to_data[ip].append(port_data)

    for ip, ports_data in ip_to_data.items():
        if ports_data:
            enriched_results.append({
                "ip": ip,
                "ports": ports_data
            })

    return enriched_results

def analyze_ports(scan_results, timeout=2):
    """
    Synchronous wrapper for analyze_ports_async.

    Args:
        scan_results: A list of dictionaries, e.g. [{"ip": "10.0.0.1", "open_ports": [80, 443]}]
        timeout: The connection timeout for checking the port.

    Returns:
        An enriched list of dictionaries detailing the protocol, TLS versions, ciphers and security warnings.
    """
    return asyncio.run(analyze_ports_async(scan_results, timeout))
