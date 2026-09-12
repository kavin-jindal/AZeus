import argparse
import io
import os
import socket
import sys
import xml.etree.ElementTree as ET
import requests

YELLOW = "\033[33m"
RESET = "\033[0m"
GREEN = "\033[32m"
BLUE = "\033[0;36m"
RED = "\033[31m"

BANNER = r'''                                    
      ▄▄▄▄   ▄▄▄▄▄▄▄▄▄                   
    ▄██▀▀██▄ ▀▀▀▀▀████                   
    ███  ███    ▄███▀  ▄█▀█▄ ██ ██ ▄█▀▀▀ 
    ███▀▀███  ▄███▀    ██▄█▀ ██ ██ ▀███▄ 
    ███  ███ █████████ ▀█▄▄▄ ▀██▀█ ▄▄▄█▀ 
                                                        
'''

AZURE_DNS = {
    # Compute & App Services
    "Virtual Machines / Cloud Services": ".cloudapp.azure.com",
    "App Service / Functions": ".azurewebsites.net",
    "App Service Kudu Console": ".scm.azurewebsites.net",
    "Container Instances": ".azurecontainer.io",
    "Container Registry": ".azurecr.io",
    "Front Door": ".azurefd.net",

    # Storage
    "Blob Storage": ".blob.core.windows.net",
    "Files": ".file.core.windows.net",
    "Queue Storage": ".queue.core.windows.net",
    "Table Storage": ".table.core.windows.net",
    "Data Lake Storage Gen2": ".dfs.core.windows.net",
    "Static Website Hosting": ".web.core.windows.net",

    # Databases
    "SQL Database": ".database.windows.net",
    "Cosmos DB": ".documents.azure.com",
    "Database for PostgreSQL": ".postgres.database.azure.com",
    "Database for MySQL": ".mysql.database.azure.com",
    "Cache for Redis": ".redis.cache.windows.net",

    # Networking, Messaging & Security
    "Traffic Manager": ".trafficmanager.net",
    "Key Vault": ".vault.azure.net",
    "Service Bus": ".servicebus.windows.net",
    "Event Hubs": ".eventhub.windows.net",
    "API Management": ".azure-api.net",

    # Identity & Management
    "Microsoft Entra ID Tenant": ".onmicrosoft.com",
    "Microsoft Entra ID Authentication": ".login.microsoftonline.com",
    "Resource Manager API": ".management.azure.com",

    # AKS / Kubernetes
    "Kubernetes Service Control Plane": ".hcp.azmk8s.io",
    "Kubernetes Service Application Routing": ".aksapp.io",
}

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, io.UnsupportedOperation):
        pass


def print_banner():
    print(BLUE + BANNER + RESET, flush=True)
    print(BLUE + "[=] Azure Enumeration & Reconnaissance Tool by Kavin Jindal" + RESET, flush=True)
    print(BLUE + "[=] Github: https://github.com/kavin-jindal" + RESET, flush=True)
    print(RED + "[!] Currently in development!" + RESET + "\n", flush=True)


def check_container(subdomain, container_name):
    public_file_discovery = '?restype=container&comp=list'
    target = f'https://{subdomain}/{container_name}'
    try:
        x = requests.get(url=f'{target}/{public_file_discovery}', timeout=8)
        if x.status_code == 200:
            print(GREEN + f'\n\t[+] {container_name}' + RESET, flush=True)
            try:
                xml_resp = ET.fromstring(x.text)
                blobs_elem = xml_resp.find('Blobs')
                if blobs_elem is not None:
                    blobs = blobs_elem.findall('Blob')
                    for blob in blobs:
                        url_elem = blob.find('Url')
                        if url_elem is not None and url_elem.text:
                            print('\t' + YELLOW + " > " + url_elem.text + RESET, flush=True)
            except (ET.ParseError, AttributeError):
                pass
            return True, None
        elif x.status_code == 409 and "PublicAccessNotPermitted" in x.text:
            return False, "PublicAccessNotPermitted"
        elif x.status_code == 403:
            return False, "Private"
    except requests.RequestException:
        pass
    return False, None


def container_enum(subdomain, wordlist_path):
    print(YELLOW + "\n\t[!] Discovered Containers" + RESET, flush=True)

    try:
        socket.getaddrinfo(subdomain, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        print(RED + f"\t[-] Blob storage endpoint '{subdomain}' does not exist or cannot be resolved." + RESET, flush=True)
        return

    if not os.path.exists(wordlist_path):
        print(RED + f"\t[-] Wordlist file not found: {wordlist_path}" + RESET, flush=True)
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.readlines()
    except Exception as e:
        print(RED + f"\t[-] Failed to read wordlist: {e}" + RESET, flush=True)
        return

    found_any = False
    for i in content:
        container_name = i.strip()
        if not container_name or container_name.startswith('#'):
            continue
        found, error = check_container(subdomain, container_name)
        if error == "PublicAccessNotPermitted":
            print(YELLOW + f"\t[-] Public access is not permitted on storage account '{subdomain}'." + RESET, flush=True)
            return
        if found:
            found_any = True

    if not found_any:
        print(YELLOW + "\t[-] No public containers discovered." + RESET, flush=True)


def parse_args():
    default_wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlist.txt')
    parser = argparse.ArgumentParser(
        description="AZeus - Azure Enumeration & Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python main.py -t contoso                     # Subdomains only
  python main.py -t contoso -c                  # Containers only
  python main.py -t contoso -c -w words.txt     # Containers with custom wordlist
  python main.py -t contoso --container backups # Check single container
  python main.py -t contoso --all               # Both subdomains and containers
"""
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="TARGET",
        help="Target name / organization prefix (e.g. contoso)"
    )
    parser.add_argument(
        "-t", "--target",
        dest="target_flag",
        metavar="TARGET",
        help="Target name / organization prefix (e.g. contoso)"
    )
    parser.add_argument(
        "-c", "--containers",
        action="store_true",
        help="Enumerate public Blob Storage containers only (using wordlist)"
    )
    parser.add_argument(
        "--container",
        metavar="NAME",
        help="Check a single specific container name for public access"
    )
    parser.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        metavar="PATH",
        default=default_wordlist,
        help=f"Path to container discovery wordlist (default: {os.path.basename(default_wordlist)})"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run both subdomain enumeration and container discovery"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress banner output"
    )
    return parser, parser.parse_args()


def main():
    parser, args = parse_args()

    target = args.target_flag or args.target
    if not target:
        parser.print_help()
        print(RED + "\n[!] Error: Target name is required. Use -t/--target <target> or specify target as argument." + RESET, flush=True)
        sys.exit(1)

    target = target.strip().lower()

    if not args.no_banner:
        print_banner()

    run_containers = args.containers or bool(args.container)
    run_subdomains = not run_containers or args.all

    if run_subdomains:
        blob_storage = False
        print(f"\n\t{YELLOW}[!] Valid Services and Subdomains\n{RESET}", flush=True)
        valid_count = 0
        for service, suffix in AZURE_DNS.items():
            domain = f'{target}{suffix}'
            try:
                socket.getaddrinfo(domain, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if 'Blob' in service:
                    blob_storage = True
                padding = max(1, 40 - len(service)) * ' '
                print(GREEN + f'\t[+]  {service}{padding}->  {domain}' + RESET, flush=True)
                valid_count += 1
            except Exception:
                pass

        if valid_count == 0:
            print(YELLOW + "\t[-] No live Azure services discovered." + RESET, flush=True)

        if blob_storage and not args.all:
            print(f"\n\t{BLUE}[*] Blob Storage discovered! Use -c/--containers to scan for public containers.{RESET}\n", flush=True)

    if run_containers or args.all:
        subdomain = f'{target}.blob.core.windows.net'
        if args.container:
            print(YELLOW + f"\n\t[!] Checking Container" + RESET, flush=True)
            found, error = check_container(subdomain, args.container)
            if error == "PublicAccessNotPermitted":
                print(YELLOW + f"\t[-] Public access is not permitted on storage account '{subdomain}'." + RESET, flush=True)
            elif not found:
                print(YELLOW + f"\t[-] Container '{args.container}' is not publicly accessible or was not found." + RESET, flush=True)
        if args.containers or (args.all and not args.container):
            container_enum(subdomain, args.wordlist)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(RED + "\n[!] Terminated." + RESET, flush=True)
        sys.exit(130)