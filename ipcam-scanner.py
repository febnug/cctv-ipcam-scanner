# install dependensi
# -------------------
# sudo apt install nmap
# sudo apt install python3-pip
# pip install python-nmap netifaces wsdiscovery tqdm --break-system-packages

# -- febnug


import nmap
import csv
import ipaddress
import netifaces
from datetime import datetime
from tqdm import tqdm
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery

RTSP_PORTS = [554, 8554, 10554]
OUTPUT_FILE = 'ipcam_scan_result.csv'

VENDOR_PREFIX = {
    "00:23:63": "Hikvision",
    "38:1C:4A": "Hikvision",
    "FC:D7:33": "Hikvision",
    "F4:4E:FD": "Hikvision",
    "E0:50:8B": "CP Plus",
    "64:5A:ED": "CP Plus",
    "AC:64:DD": "CP Plus"
}

def get_local_subnet():
    gws = netifaces.gateways()
    default_iface = gws.get('default', {}).get(netifaces.AF_INET, [None, None])[1]
    if not default_iface:
        raise RuntimeError("Tidak bisa menemukan interface default")

    addrs = netifaces.ifaddresses(default_iface)
    iface_info = addrs.get(netifaces.AF_INET, [{}])[0]
    ip = iface_info.get('addr')
    netmask = iface_info.get('netmask')

    if not ip or not netmask:
        raise RuntimeError("Gagal mendapatkan IP atau netmask")

    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    print(f"[INFO] Terdeteksi subnet aktif: {network}")
    return str(network)

def identify_vendor(mac):
    mac_prefix = mac.upper()[0:8]
    return VENDOR_PREFIX.get(mac_prefix, "Unknown")

def build_rtsp_url(ip, port):
    return f"rtsp://<user>:<password>@{ip}:{port}/Streaming/Channels/101"

def detect_onvif_ips():
    print("[ONVIF] Mendeteksi kamera ONVIF via WS-Discovery...")
    wsd = WSDiscovery()
    wsd.start()
    services = wsd.searchServices(timeout=3)
    ip_set = set()
    for service in services:
        for xaddr in service.getXAddrs():
            if 'http://' in xaddr:
                try:
                    ip = xaddr.split("//")[1].split("/")[0].split(":")[0]
                    ip_set.add(ip)
                except IndexError:
                    continue
    wsd.stop()
    return ip_set

def scan_network(network):
    scanner = nmap.PortScanner()
    hosts = list(ipaddress.IPv4Network(network).hosts())
    print(f"[SCAN] Memindai {len(hosts)} host di jaringan {network} ...")

    results = []
    onvif_ips = detect_onvif_ips()

    for host in tqdm(hosts, desc="Scanning IP", ncols=80):
        ip = str(host)
        try:
            scanner.scan(hosts=ip, arguments=f'-p {",".join(map(str, RTSP_PORTS))} --open')
        except Exception:
            continue

        if ip not in scanner.all_hosts():
            continue

        host_info = scanner[ip]
        mac = host_info['addresses'].get('mac', 'Unknown')
        vendor = identify_vendor(mac) if mac != 'Unknown' else 'Unknown'
        open_ports = []
        for proto in host_info.all_protocols():
            open_ports += host_info[proto].keys()

        for port in RTSP_PORTS:
            if port in open_ports:
                results.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'port': port,
                    'rtsp_url': build_rtsp_url(ip, port),
                    'onvif': ip in onvif_ips
                })
                break  # cukup 1 port yang terbuka
    return results

def save_to_csv(devices):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(OUTPUT_FILE, mode='w', newline='') as csvfile:
        fieldnames = ['IP', 'MAC', 'Vendor', 'Port', 'RTSP URL', 'ONVIF', 'Detected Time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for dev in devices:
            writer.writerow({
                'IP': dev['ip'],
                'MAC': dev['mac'],
                'Vendor': dev['vendor'],
                'Port': dev['port'],
                'RTSP URL': dev['rtsp_url'],
                'ONVIF': 'Yes' if dev['onvif'] else 'No',
                'Detected Time': timestamp
            })
    print(f"[SAVE] Hasil disimpan ke {OUTPUT_FILE}")

# --- MAIN ---
if __name__ == "__main__":
    try:
        network = get_local_subnet()
        devices = scan_network(network)

        print("\n[HASIL DETEKSI IP CAMERA]")
        if not devices:
            print("Tidak ada IP Camera ditemukan.")
        else:
            for idx, cam in enumerate(devices, 1):
                print(f"{idx}. IP     : {cam['ip']}")
                print(f"   MAC    : {cam['mac']}")
                print(f"   Vendor : {cam['vendor']}")
                print(f"   Port   : {cam['port']}")
                print(f"   RTSP   : {cam['rtsp_url']}")
                print(f"   ONVIF  : {'Yes' if cam['onvif'] else 'No'}\n")

            save_to_csv(devices)

    except Exception as e:
        print(f"[ERROR] {e}")
