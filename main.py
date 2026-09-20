import socket, requests
import xml.etree.ElementTree as ET

YELLOW="\033[33m"
RESET="\033[0m"
GREEN="\033[32m"
BLUE="\033[0;36m"
RED="\033[31m"
try: 
    banner = r'''                                    
      ▄▄▄▄   ▄▄▄▄▄▄▄▄▄                   
    ▄██▀▀██▄ ▀▀▀▀▀████                   
    ███  ███    ▄███▀  ▄█▀█▄ ██ ██ ▄█▀▀▀ 
    ███▀▀███  ▄███▀    ██▄█▀ ██ ██ ▀███▄ 
    ███  ███ █████████ ▀█▄▄▄ ▀██▀█ ▄▄▄█▀ 
                                                        
    '''
    print(BLUE+banner+RESET)
    print(BLUE+"[=] Azure Enumeration & Reconnaissance Tool by Kavin Jindal"+RESET)
    print(BLUE+"[=] Github: https://github.com/kavin-jindal"+RESET)

    print(RED+"[!] Currently in development!"+RESET+"\n")
    usin = input(YELLOW+"[?] Enter target name>> "+RESET)
    azure_dns = {
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
    valid_resource = {}
    for i in azure_dns.keys():       
        try:
            test = socket.getaddrinfo(f'{usin}{azure_dns[i]}', 0, socket.AF_UNSPEC, socket.SOCK_STREAM)            
            r_name = f'{usin}{azure_dns[i]}'
            valid_resource[i] = r_name    
        except Exception as e:
            None
    blob_storage=False
    print(f"\n\t{YELLOW}[!] Valid Services and Subdomains\n{RESET}")
    for i in valid_resource.keys():
        x = 30-len(i)
        if 'Blob' in i:
            blob_storage=True
        print(GREEN+'\t[+] ',  i, f'{x*' '} -> ', valid_resource[i]+RESET)
    def container_enum(subdomain):
        public_file_discovery = '?restype=container&comp=list'
        f = open('wordlist.txt', 'r')
        content = f.readlines()
        print(YELLOW+"\n\t[!] Discovered Containers"+RESET)
        for i in content:
            i = i.strip('\n')
            target=f'https://{subdomain}/{i}'
            x = requests.get(url=f'{target}/{public_file_discovery}')            
            if x.status_code not in [404, 400]:
                print(GREEN + f'\n\t[+] {i}'+RESET)
                xml_resp = x.text
                xml_resp = ET.fromstring(xml_resp)
                blobs = xml_resp.find('Blobs').findall('Blob')
                for blob in blobs:
                    print('\t'+YELLOW+" > "+blob.find('Url').text+RESET)  
    if blob_storage is True:        
        container_enum(f'{usin}.blob.core.windows.net')
except KeyboardInterrupt:
    print(RED+"\n[!] Terminated."+RESET)
