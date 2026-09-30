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


def interpret_credential_data(response_data):
    ests = response_data.get("EstsProperties") or {}
    creds = response_data.get("Credentials") or {}
    branding_list = ests.get("UserTenantBranding") or []

    # 1. Account existence
    if_exists = response_data.get("IfExistsResult")
    if_exists_map = {
        0: "Account exists (Valid User)",
        1: "Account does not exist",
        5: "Account or domain does not exist",
        6: "Domain not registered in Microsoft Entra ID",
    }
    account_status = if_exists_map.get(if_exists, f"Unknown status code ({if_exists})")

    # 2. Throttling
    throttle = response_data.get("ThrottleStatus")
    throttle_status = "Rate limited by Microsoft (Throttled)" if throttle == 1 else "Normal (Not throttled)"

    # 3. Tenant governance
    is_unmanaged = response_data.get("IsUnmanaged")
    if is_unmanaged is True:
        tenant_mgmt = "Unmanaged / Viral Tenant (Self-created, no IT admin takeover)"
    elif is_unmanaged is False:
        tenant_mgmt = "Managed Tenant (Formally administered by IT organization)"
    else:
        tenant_mgmt = "Unknown"

    # 4. Self-service signup
    signup_disallowed = response_data.get("IsSignupDisallowed")
    if signup_disallowed is True:
        signup_status = "Disabled (Users cannot self-register accounts in this domain)"
    elif signup_disallowed is False:
        signup_status = "Enabled (Self-service user registration is allowed)"
    else:
        signup_status = "Unknown"

    # 5. Domain architecture
    domain_type = ests.get("DomainType")
    domain_type_map = {
        1: "Unknown",
        2: "Federated (Authenticates via external IdP e.g., ADFS, Okta, Ping)",
        3: "Managed / Cloud-Only (Authenticates directly with Microsoft Entra ID)",
        4: "Hybrid / Managed",
    }
    domain_status = domain_type_map.get(domain_type, f"DomainType {domain_type}" if domain_type is not None else "Not available")

    # 6. Federation redirect
    fed_url = response_data.get("FederationRedirectUrl")
    fed_status = fed_url if fed_url else "None (Direct Microsoft authentication)"

    # 7. Preferred credential
    pref_cred = creds.get("PrefCredential")
    pref_cred_map = {
        1: "Password authentication",
        2: "Federation / External IdP",
        3: "Certificate-based authentication",
        4: "FIDO2 security key",
        5: "Windows Hello / Remote NGC",
    }
    pref_cred_status = pref_cred_map.get(pref_cred, f"Type {pref_cred}" if pref_cred is not None else "Not available")

    # 8. Password status
    has_pwd = creds.get("HasPassword")
    if has_pwd is True:
        has_pwd_status = "Yes (Password authentication enabled on this account)"
    elif has_pwd is False:
        has_pwd_status = "No (Passwordless or no password configured)"
    else:
        has_pwd_status = "Unknown"

    # 9. Alternate authentication methods
    alt_methods = []
    if creds.get("FidoParams"):
        alt_methods.append("FIDO2 Security Key")
    if creds.get("CertAuthParams"):
        alt_methods.append("Certificate Auth")
    if creds.get("RemoteNgcParams"):
        alt_methods.append("Windows Hello (Remote NGC)")
    if creds.get("GoogleParams"):
        alt_methods.append("Google Federation")
    if creds.get("FacebookParams"):
        alt_methods.append("Facebook Federation")
    alt_auth_status = ", ".join(alt_methods) if alt_methods else "None advertised (Standard login flow)"

    # 10. Branding & Portal UX
    branding_theme = "Default Microsoft branding"
    kmsi_status = "Not specified"
    sspr_status = "Not specified"

    if branding_list:
        first_branding = branding_list[0]
        bg = first_branding.get("BackgroundColor")
        if bg and bg.lower() != "#ffffff":
            branding_theme = f"Custom background color ({bg})"
        else:
            branding_theme = "Default Microsoft theme"

        kmsi_disabled = first_branding.get("KeepMeSignedInDisabled")
        if kmsi_disabled is False:
            kmsi_status = "Allowed ('Stay signed in' prompt enabled)"
        elif kmsi_disabled is True:
            kmsi_status = "Disabled ('Stay signed in' prompt suppressed)"

        layout = first_branding.get("LayoutTemplateConfig") or {}
        hide_pwd = layout.get("hideForgotMyPassword")
        hide_cant_access = layout.get("hideCantAccessYourAccount")
        if hide_pwd is False or hide_cant_access is False:
            sspr_status = "Visible (Self-service recovery links shown)"
        elif hide_pwd is True and hide_cant_access is True:
            sspr_status = "Hidden (Self-service recovery links disabled)"

    return [
        ("Account Validity", account_status),
        ("Identity Architecture", domain_status),
        ("Federation Redirect", fed_status),
        ("Primary Credential", pref_cred_status),
        ("Password Enabled", has_pwd_status),
        ("Alternative Auth", alt_auth_status),
        ("Tenant Governance", tenant_mgmt),
        ("Self-Service Signup", signup_status),
        ("Rate Limiting", throttle_status),
        ("Portal Branding", branding_theme),
        ("Keep Me Signed In", kmsi_status),
        ("Password Reset (SSPR)", sspr_status),
    ]


def enumerate_username(username):
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    payload = {
        "username": username,
        "isOtherIdpSupported": True,
    }
    headers = {
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(url, json=payload, headers=headers)
        response_data = resp.json()
    except Exception as e:
        print(f"\t{RED}[!] Error querying Microsoft login API: {e}{RESET}")
        return

    print(f"\n\t{YELLOW}[!] Username Enumeration{RESET}")

    if_exists = response_data.get("IfExistsResult")
    if if_exists == 0:
        print(f"\t{GREEN}[+] Account Exists: {username}{RESET}")
    else:
        print(f"\t{RED}[!] Account Does Not Exist / Invalid: {username}{RESET}")

    # Key Findings section
    findings = interpret_credential_data(response_data)
    print(f"\n\t{YELLOW}[*] Key Findings{RESET}")
    field_width = max(len(label) for label, _ in findings)
    for label, text in findings:
        print(f"\t    {BLUE}{label:<{field_width}}{RESET} : {GREEN}{text}{RESET}")
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
