import argparse
import socket
import xml.etree.ElementTree as ET

import requests


YELLOW = "\033[33m"
RESET = "\033[0m"
GREEN = "\033[32m"
BLUE = "\033[0;36m"
RED = "\033[31m"

AZURE_DNS = {
    "Virtual Machines / Cloud Services": ".cloudapp.azure.com",
    "App Service / Functions": ".azurewebsites.net",
    "App Service Kudu Console": ".scm.azurewebsites.net",
    "Container Instances": ".azurecontainer.io",
    "Container Registry": ".azurecr.io",
    "Front Door": ".azurefd.net",
    "Blob Storage": ".blob.core.windows.net",
    "Files": ".file.core.windows.net",
    "Queue Storage": ".queue.core.windows.net",
    "Table Storage": ".table.core.windows.net",
    "Data Lake Storage Gen2": ".dfs.core.windows.net",
    "Static Website Hosting": ".web.core.windows.net",
    "SQL Database": ".database.windows.net",
    "Cosmos DB": ".documents.azure.com",
    "Database for PostgreSQL": ".postgres.database.azure.com",
    "Database for MySQL": ".mysql.database.azure.com",
    "Cache for Redis": ".redis.cache.windows.net",
    "Traffic Manager": ".trafficmanager.net",
    "Key Vault": ".vault.azure.net",
    "Service Bus": ".servicebus.windows.net",
    "Event Hubs": ".eventhub.windows.net",
    "API Management": ".azure-api.net",
    "Microsoft Entra ID Tenant": ".onmicrosoft.com",
    "Microsoft Entra ID Authentication": ".login.microsoftonline.com",
    "Resource Manager API": ".management.azure.com",
    "Kubernetes Service Control Plane": ".hcp.azmk8s.io",
    "Kubernetes Service Application Routing": ".aksapp.io",
}


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Azure target name")
    parser.add_argument("-U", "--userlist", metavar="PATH", help="Path to username wordlist")
    parser.add_argument("-u", "--username", metavar="NAME", help="Single username to enumerate")
    return parser.parse_args()


def print_banner():
    banner = r'''                                    
      ▄▄▄▄   ▄▄▄▄▄▄▄▄▄                   
    ▄██▀▀██▄ ▀▀▀▀▀████                   
    ███  ███    ▄███▀  ▄█▀█▄ ██ ██ ▄█▀▀▀ 
    ███▀▀███  ▄███▀    ██▄█▀ ██ ██ ▀███▄ 
    ███  ███ █████████ ▀█▄▄▄ ▀██▀█ ▄▄▄█▀ 
                                                        
    '''
    print(BLUE + banner + RESET)
    print(BLUE + "[=] Azure Enumeration & Reconnaissance Tool by Kavin Jindal" + RESET)
    print(BLUE + "[=] Github: https://github.com/kavin-jindal" + RESET)
    print(RED + "[!] Currently in development!" + RESET + "\n")


def enumerate_subdomains(target):
    valid_resource = {}
    for service, suffix in AZURE_DNS.items():
        try:
            socket.getaddrinfo(
                f"{target}{suffix}",
                0,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
            valid_resource[service] = f"{target}{suffix}"
        except Exception:
            pass

    print(f"\n\t{YELLOW}[!] Valid Services and Subdomains\n{RESET}")
    for service, resource in valid_resource.items():
        spacing = 30 - len(service)
        print(GREEN + "\t[+] ", service, " " * spacing + " -> ", resource + RESET)

    return "Blob Storage" in valid_resource


def enumerate_containers(subdomain):
    public_file_discovery = "?restype=container&comp=list"
    with open("wordlist.txt", "r") as wordlist:
        content = wordlist.readlines()

    print(YELLOW + "\n\t[!] Discovered Containers" + RESET)
    for container in content:
        container = container.strip("\n")
        target = f"https://{subdomain}/{container}"
        response = requests.get(url=f"{target}/{public_file_discovery}")
        if response.status_code not in [404, 400]:
            print(GREEN + f"\n\t[+] {container}" + RESET)
            xml_resp = ET.fromstring(response.text)
            blobs = xml_resp.find("Blobs").findall("Blob")
            for blob in blobs:
                print("\t" + YELLOW + " > " + blob.find("Url").text + RESET)


def main():
    print_banner()
    args = parse_arguments()
    blob_storage = enumerate_subdomains(args.target)
    if blob_storage:
        enumerate_containers(f"{args.target}.blob.core.windows.net")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(RED + "\n[!] Terminated." + RESET)
