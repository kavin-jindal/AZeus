import argparse
import socket
import sys
import xml.etree.ElementTree as ET
import requests

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


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
    if len(sys.argv) == 1:
        parser.error("no arguments provided")
    parser.add_argument("-S", '--subdomain', metavar="TENANT", help="Enumerate services and subdomains for a tenant")
    parser.add_argument("-B", '--blob', metavar="TENANT", help='Enumerate Blob Containers')
    parser.add_argument("-U", "--userlist", metavar="PATH", help="Path to username wordlist")
    parser.add_argument("-u", "--username", metavar="DOMAIN", help="Single username to enumerate passively")
    parser.add_argument('-t', '--tenant', metavar="TENANT", help='Passively enumerate a tenant')
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


def enumerate_username(username):
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    payload = {
        "username": username,
        "isOtherIdpSupported": True,
    }
    headers = {
        "Content-Type": "application/json",
    }

    resp = requests.post(url, json=payload, headers=headers)
    response_data = resp.json()
    def format_val(val):
        if val is None or val == "" or val == {} or val == []:
            return "Not available"
        if isinstance(val, list):
            return ", ".join(str(item) for item in val)
        return str(val)

    def flatten_dict(d, prefix=""):
        items = []
        for k, v in d.items():
            key_name = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict) and v:
                items.extend(flatten_dict(v, key_name))
            else:
                items.append((key_name, format_val(v)))
        return items

    categories = {}

    # Category 1: Account & Tenant Status
    ests = response_data.get("EstsProperties") or {}
    categories["Account & Tenant Status"] = [
        ("IfExistsResult", format_val(response_data.get("IfExistsResult"))),
        ("ThrottleStatus", format_val(response_data.get("ThrottleStatus"))),
        ("IsUnmanaged", format_val(response_data.get("IsUnmanaged"))),
        ("IsSignupDisallowed", format_val(response_data.get("IsSignupDisallowed"))),
        ("DomainType", format_val(ests.get("DomainType"))),
        ("FederationRedirectUrl", format_val(response_data.get("FederationRedirectUrl"))),
    ]

    # Category 2: Authentication & Credentials
    creds = response_data.get("Credentials") or {}
    categories["Authentication & Credentials"] = [
        ("PrefCredential", format_val(creds.get("PrefCredential"))),
        ("HasPassword", format_val(creds.get("HasPassword"))),
        ("RemoteNgcParams", format_val(creds.get("RemoteNgcParams"))),
        ("FidoParams", format_val(creds.get("FidoParams"))),
        ("CertAuthParams", format_val(creds.get("CertAuthParams"))),
        ("GoogleParams", format_val(creds.get("GoogleParams"))),
        ("FacebookParams", format_val(creds.get("FacebookParams"))),
    ]

    # Category 3: Tenant Branding & Layout Configuration
    branding_list = ests.get("UserTenantBranding")
    if not branding_list:
        categories["Tenant Branding"] = [("Branding Data", "Not available")]
    else:
        for idx, branding in enumerate(branding_list):
            suffix = f" [{idx}]" if len(branding_list) > 1 else ""
            b_items = []
            layout_items = []
            for k, v in branding.items():
                if k == "LayoutTemplateConfig" and isinstance(v, dict):
                    layout_items.extend(flatten_dict(v))
                elif isinstance(v, dict):
                    b_items.extend(flatten_dict(v, k))
                else:
                    b_items.append((k, format_val(v)))

            categories[f"Tenant Branding{suffix}"] = b_items
            if layout_items:
                categories[f"Branding Layout Configuration{suffix}"] = layout_items

    print(f"\n\t{YELLOW}[!] Username Enumeration{RESET}")
    for cat_name, fields in categories.items():
        print(f"\n\t{YELLOW}[*] {cat_name}{RESET}")
        field_width = max(len(k) for k, _ in fields)
        for label, value in fields:
            print(f"\t    {BLUE}{label:<{field_width}}{RESET} : {GREEN}{value}{RESET}")

    if response_data.get("IfExistsResult") != 0:
        print(RED + f"\n\t[!] Username does not exist: {username}" + RESET)
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
    subdomain=f"{subdomain}.blob.core.windows.net"
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
    blob_storage = (args.subdomain)
    tenant = args.tenant
    container = args.blob
    username = args.username
    if blob_storage:
        enumerate_subdomains(blob_storage)
    if container:
        enumerate_containers(container)
    
    if username:
        enumerate_username(username)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(RED + "\n[!] Terminated." + RESET)
