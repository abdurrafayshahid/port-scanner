import socket
import sys
import threading
import psutil
from queue import Queue, Empty
from scapy.all import IP, TCP, sr1, send, conf

conf.verb = 0
print_lock = threading.Lock()

def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown"

def tcp_connect_check(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        status = sock.connect_ex((target_ip, port))
        sock.close()
        return status == 0
    except OSError:
        return False

def count_open_ports(target_ip, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]):
    count = 0
    for port in ports:
        if tcp_connect_check(target_ip, port):
            count += 1
    return count

def get_local_addresses():
    addresses = []
    interfaces = psutil.net_if_addrs()
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                addresses.append({
                    "ip": address.address,
                    "interface": interface_name
                })
    return addresses

def tcp_connect_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        status = sock.connect_ex((target_ip, port))
        
        if status == 0:
            service = get_service_name(port)
            try:
                banner = sock.recv(1024).decode(errors='ignore').strip()
                info = f"Port {port}: OPEN | Service: {service} | Banner: {banner}" if banner else f"Port {port}: OPEN | Service: {service}"
            except socket.timeout:
                info = f"Port {port}: OPEN | Service: {service}"
            
            with print_lock:
                print(info)
            sock.close()
            return True
        
        sock.close()
        return False
    except OSError:
        return False

def syn_scan(target_ip, port):
    try:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            send(IP(dst=target_ip) / TCP(dport=port, flags="R"), verbose=0)
            service = get_service_name(port)
            with print_lock:
                print(f"Port {port}: OPEN (SYN) | Service: {service}")
            return True
        return False
    except OSError:
        return False

def worker(target_ip, port_queue, scan_type):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
            if scan_type == 'syn':
                syn_scan(target_ip, port)
            else:
                tcp_connect_scan(target_ip, port)
            port_queue.task_done()
        except Empty:
            break

def run_port_scan(target_ip, ports, scan_type, threads=20):
    print(f"\n--- Starting {scan_type.upper()} scan on {target_ip} ---")
    port_queue = Queue()
    for port in ports:
        port_queue.put(port)
    
    thread_pool = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, args=(target_ip, port_queue, scan_type))
        t.daemon = True
        t.start()
        thread_pool.append(t)
    
    port_queue.join()
    print("--- Scan complete ---\n")

def main():
    print("""
█▀█ █▀█ █▀█ ▀█▀   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█▀▀ █▄█ █▀▄ ░█░   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
    """)
    
    local_ips = get_local_addresses()
    
    if not local_ips:
        print("No local IPv4 addresses found.")
    else:
        for i, addr in enumerate(local_ips, 1):
            print(f"Checking {addr['ip']}...", end="\r")
            open_count = count_open_ports(addr['ip'], [21, 22, 80, 443])
            print(f"{i}. {addr['ip']} ({addr['interface']}) [{open_count} common ports open]")

    target_ip = None

    while target_ip is None:
        try:
            choice = input(f"\nSelect an address to scan (0-{len(local_ips)}): ").strip()
            if choice == '0':
                target_ip = input("Enter target IP or hostname: ").strip()
                if not target_ip:
                    print("Target cannot be empty.")
                    target_ip = None
                break
            
            if choice.isdigit() and 1 <= int(choice) <= len(local_ips):
                target_ip = local_ips[int(choice)-1]['ip']
                break
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    print(f"\nTarget selected: {target_ip}")
    
    ports = []
    while not ports:
        port_input = input("Enter port range (e.g., 1-1024) or specific ports (80,443) [Default 1-1024]: ").strip()
        
        try:
            if not port_input:
                ports = list(range(1, 1025))
            elif "-" in port_input:
                parts = port_input.split("-")
                if len(parts) != 2:
                    raise ValueError("Invalid range format.")
                
                start = int(parts[0])
                end = int(parts[1])
                
                if start > end:
                    raise ValueError("Start port cannot be greater than end port.")
                if start < 1 or end > 65535:
                    raise ValueError("Ports must be between 1 and 65535.")
                
                ports = list(range(start, end + 1))
            else:
                parts = port_input.split(",")
                for p in parts:
                    p = p.strip()
                    if not p: continue
                    val = int(p)
                    if 1 <= val <= 65535:
                        ports.append(val)
                    else:
                        raise ValueError(f"Port {val} out of range.")
            
            if not ports:
                raise ValueError("No valid ports provided.")

        except ValueError as e:
            print(f"Error: {e}")
            print("Please enter valid numeric ports.\n")
            ports = []

    is_syn = input("Use SYN scan? (requires root) [y/N]: ").lower().strip() == 'y'
    run_port_scan(target_ip, ports, 'syn' if is_syn else 'connect')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
