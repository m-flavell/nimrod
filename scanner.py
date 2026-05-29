import asyncio
import ipaddress
from collections import defaultdict

async def check_port(ip, port, semaphore, timeout):
    async with semaphore:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return ip, port
        except Exception:
            return ip, None

async def scan_range_async(ips, ports, concurrency, timeout):
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(asyncio.create_task(check_port(ip, port, semaphore, timeout)))

    results = await asyncio.gather(*tasks)

    ip_to_ports = defaultdict(list)
    for ip, port in results:
        if port is not None:
            ip_to_ports[ip].append(port)

    return ip_to_ports

def scan_ports(ip_range_str, ports=range(1, 1025), concurrency=1000, timeout=0.5):
    """
    Scans a range of IPs for open ports.

    Args:
        ip_range_str: A string containing start and end IP addresses separated by a space.
        ports: An iterable of ports to scan. Defaults to 1-1024.
        concurrency: The maximum number of concurrent connection attempts.
        timeout: The timeout in seconds for each connection attempt.

    Returns:
        A list of dictionaries, where each dictionary contains an "ip" and a list of "open_ports".
        If no open ports are detected for an IP, it is not included in the list.
    """
    try:
        start_ip_str, end_ip_str = ip_range_str.strip().split()
    except ValueError:
        raise ValueError("ip_range_str must contain exactly two IP addresses separated by a space")

    start_ip = int(ipaddress.IPv4Address(start_ip_str))
    end_ip = int(ipaddress.IPv4Address(end_ip_str))

    if start_ip > end_ip:
        start_ip, end_ip = end_ip, start_ip

    ips = [str(ipaddress.IPv4Address(i)) for i in range(start_ip, end_ip + 1)]
    ip_to_ports = asyncio.run(scan_range_async(ips, ports, concurrency, timeout))

    output = []
    for ip in ips:
        open_ports = sorted(ip_to_ports.get(ip, []))
        if open_ports:
            output.append({
                "ip": ip,
                "open_ports": open_ports
            })

    return output
