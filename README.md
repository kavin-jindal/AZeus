<div align="center">

# AZeus

**Azure Enumeration & Reconnaissance Tool**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Cloud-Microsoft%20Azure%20%7C%20Entra%20ID-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]()

Fast, modular reconnaissance and enumeration tool for Microsoft Azure and Microsoft Entra ID (Azure AD) attack surface mapping.

</div>

---

**[!] DISCLAIMER** This tool is designed for authorized security testing, red teaming, CTFs, and educational research only. Always obtain explicit written authorization from the target organization before running enumeration or credential testing.

---

## Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [CLI Options & Usage](#-cli-options--usage)
- [Raw Endpoints Used](#-raw-endpoints-used)
  - [1. User Realm Discovery (`getuserrealm.srf`)](#1-user-realm-discovery-getuserrealmsrf---pre-auth)
  - [2. Exchange Autodiscover v1.0 JSON API](#2-exchange-autodiscover-v10-json-api)
  - [3. GetCredentialType API (Passive User Enumeration)](#3-getcredentialtype-api-passive-user-enumeration)
  - [4. OpenID Connect Discovery (Tenant ID Extraction)](#4-openid-connect-discovery-tenant-id-extraction)
  - [5. Azure Blob Storage REST API](#5-azure-blob-storage-rest-api)
  - [6. OAuth 2.0 ROPC Token Endpoint (Active Account Validation)](#6-oauth-20-ropc-token-endpoint-active-account-validation)
- [Installation](#-installation)
- [Example Workflows](#-example-workflows)
- [License](#-license)

---

## [*] Overview

**AZeus** is an enumeration and reconnaissance tool for **Microsoft Azure** and **Microsoft Entra ID (formerly Azure AD)**. It helps you map out a target organization's public Azure attack surface through pre-authentication enumeration—finding live services and subdomains, exposed blob storage, tenant identity architecture, mailbox routing, valid usernames, and credential checks.

---

## [+] Key Features

- **Pre-Auth Tenant Enumeration:** Queries public endpoints to pull tenant Directory IDs (GUID), federation setup (Managed vs Federated), STS login URLs, and tenant brand names without logging in.
- **Pre-Auth Username Enumeration:** Checks whether user accounts exist passively through Microsoft's credential validation API without triggering sign-in logs or lockouts.
- **Identity & Authentication Profiling:** Identifies supported authentication methods (passwords, FIDO2 keys, certificates, Windows Hello, external federation) along with self-service registration and password reset settings.
- **Azure Service & Subdomain Mapping:** Probes **27 Azure DNS suffixes** across Compute, Databases, Storage, Kubernetes, Networking, and Identity to discover live assets.
- **Public Blob Storage Discovery:** Scans for publicly readable Azure Blob containers and extracts direct URLs to accessible files.
- **Account & Credential Validation:** Tests accounts and passwords against Microsoft's OAuth token endpoint to check for valid logins, incorrect passwords, expired credentials, or MFA requirements.

---

## [>] CLI Options & Usage

```text
usage: main.py [-h] [-S TENANT] [-B TENANT] [-T TENANT] [-u DOMAIN] [-U PATH] [-p PASSWORD] [-P PATH]

options:
  -h, --help            Show this help message and exit
  -S TENANT, --subdomain TENANT
                        Enumerate services and subdomains for a tenant
  -B TENANT, --blob TENANT
                        Enumerate public Blob Storage containers
  -T TENANT, --tenant TENANT
                        Enumerate tenant metadata and OpenID configuration
  -u DOMAIN, --username DOMAIN
                        Enumerate a username on a tenant passively
  -U PATH, --userlist PATH
                        Path to username wordlist
  -p PASSWORD, --password PASSWORD
                        Enumerate a user account on a tenant with password
  -P PATH, --passlist PATH
                        Path to password wordlist
```

---

## [^] Raw Endpoints Used

AZeus interacts with several public pre-authentication endpoints and Microsoft's OAuth token endpoint:

```
+-----------------------------------------------------------------------------------+
|                                       AZeus                                       |
+---------+-------------------+-------------------+-------------------+-------------+
          |                   |                   |                   |
          v                   v                   v                   v
   getuserrealm.srf      Autodiscover       GetCredentialType     OpenID Config
   (Pre-Auth Realm)    (Mailbox Routing)   (Pre-Auth Users)     (Tenant ID GUID)
          |                   |                   |                   |
          +-------------------+-------------------+-------------------+
                              |
                              v
                   OAuth 2.0 Token Endpoint
                   (Credential Validation)
```

### 1. User Realm Discovery (`getuserrealm.srf`) - Pre-Auth

* **Endpoint:** `GET https://login.microsoftonline.com/getuserrealm.srf?login={login}&json=1`
* **Authentication:** None (Public / Pre-Auth)
* **Purpose:** Queries Microsoft's identity realm lookup service to check whether a domain authenticates directly with Microsoft Entra ID or delegates to an external Identity Provider (IdP).
* **Key Fields Extracted:**
  * `NameSpaceType`: Returns `Managed` (cloud-only) or `Federated` (external IdP).
  * `FederationBrandName`: Display name of the tenant organization.
  * `AuthURL`: If federated, provides the external Security Token Service (STS) endpoint (e.g. ADFS, Okta, Ping Identity).
  * `CloudInstanceName`: Identifies commercial cloud (`microsoftonline.com`), US Gov (`login.microsoftonline.us`), or regional cloud instances.

### 2. Exchange Autodiscover v1.0 JSON API

* **Endpoints:**
  * Primary: `GET https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{email}?Protocol=res`
  * Fallback: `GET https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{email}?Protocol=REST`
* **Authentication Required:** **None (Public)**
* **Purpose:** Determines mailbox routing and tenant email configuration without authentication.
* **Interpretation:**
  * `HTTP 302 Found`: Location header redirects to the target mailbox server (identifies on-premises Exchange hybrid hosts or tenant routing targets).
  * `HTTP 200 OK`: Confirms a valid, active mailbox hosted directly in Exchange Online.
  * `HTTP 404` / `Protocol_UnsupportedProtocol`: Indicates the user does not have an Exchange mailbox or is not hosted on Exchange Online.

### 3. GetCredentialType API (Passive User Enumeration)

* **Endpoint:** `POST https://login.microsoftonline.com/common/GetCredentialType`
* **Authentication Required:** **None (Public)**
* **Request Payload:**
  ```json
  {
    "username": "user@target.com",
    "isOtherIdpSupported": true
  }
  ```
* **Purpose:** Powers Microsoft's login interface (`login.microsoftonline.com`) to determine which authentication prompts to display to the user.
* **Key Fields Extracted:**
  * `IfExistsResult`:
    * `0`: **Account exists** (Valid user account).
    * `1`: Account does not exist.
    * `5`: Account or domain does not exist.
    * `6`: Domain not registered in Microsoft Entra ID.
  * `Credentials`:
    * `PrefCredential`: Preferred auth method (1=Password, 2=Federation, 3=Certificate, 4=FIDO2, 5=Windows Hello).
    * `HasPassword`: Boolean indicating if a password is configured on the account.
    * `FidoParams`, `CertAuthParams`, `RemoteNgcParams`, `GoogleParams`, `FacebookParams`: Flags advertising hardware keys, smartcards, Windows Hello, or external federation.
  * `EstsProperties`:
    * `DomainType`: 2 (Federated), 3 (Managed / Cloud-Only), 4 (Hybrid).
    * `UserTenantBranding`: Custom background colors, KMSI (`KeepMeSignedInDisabled`), and SSPR (`hideForgotMyPassword`) configuration.
  * `IsUnmanaged`: Identifies "viral" tenants created by self-service users without IT takeover.
  * `ThrottleStatus`: 1 if Microsoft has rate-limited requests from the caller's IP.

### 4. OpenID Connect Discovery (Tenant ID Extraction)

* **Endpoint:** `GET https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration`
* **Authentication Required:** **None (Public)**
* **Purpose:** Queries the public OIDC metadata configuration document for the tenant.
* **Key Fields Extracted:**
  * `token_endpoint`: Typically structured as `https://login.microsoftonline.com/{TENANT_ID_GUID}/oauth2/v2.0/token`.
  * AZeus extracts the 36-character Directory ID (Tenant GUID) from the endpoint path.

### 5. Azure Blob Storage REST API

* **Endpoint:** `GET https://{subdomain}.blob.core.windows.net/{container}?restype=container&comp=list`
* **Authentication Required:** **None (Tests for Anonymous Public Read)**
* **Purpose:** Probes for open blob containers and dumps exposed files.
* **Interpretation:**
  * `HTTP 200 OK`: Container has public read access enabled. Returns an XML document listing all blobs and their URLs.
  * `HTTP 404 Not Found`: Container does not exist.
  * `HTTP 400 / 403`: Container exists but anonymous listing is blocked.

### 6. OAuth 2.0 ROPC Token Endpoint (Active Account Validation)

* **Endpoint:** `POST https://login.microsoftonline.com/{domain}/oauth2/token`
* **Request Format:** `application/x-www-form-urlencoded`
* **Payload:**
  ```text
  client_id=1b730954-1685-4b74-9bfd-dac224a7b894
  client_info=1
  resource=https://graph.windows.net
  username={username}
  password={password}
  grant_type=password
  scope=openid
  ```
  *(Uses the Microsoft Azure PowerShell / Office client ID)*
* **Purpose:** Tests credentials via Resource Owner Password Credentials (ROPC) grant type against Microsoft Entra ID.
* **Condition-Based Outcome Evaluation:**

| Response / Code | Assessment | Display Output |
| :--- | :--- | :--- |
| **HTTP 200** | Credentials valid & token acquired | `[+] Exists` / `Password Status : Valid (Login Successful)` |
| **50034** | User does not exist in directory | `[-] Account Does Not Exist / Invalid: <user>` *(Red scheme)* |
| **50059** | Tenant or domain does not exist | `[-] Account Does Not Exist / Invalid: <user>` *(Red scheme)* |
| **50126** | User exists, password incorrect | `[*] Exists` / `Password Status : Incorrect` |
| **50053** | User exists, Smart Lockout triggered | `[*] Exists` / `Account State : Locked Out` |
| **50057** | User exists, disabled by admin | `[*] Exists` / `Account State : Disabled` |
| **50055** | User exists, password expired | `[*] Exists` / `Password Status : Expired` |
| **50056** | User exists, passwordless account | `[*] Exists` / `Password Status : No Password Set` |
| **50076 / 50079** | Password valid, MFA challenge required | `[*] Exists` / `Password Status : Correct (MFA Required)` |
| **53003 / 50158** | Password valid, blocked by Conditional Access | `[*] Exists` / `Password Status : Correct (Blocked by Conditional Access)` |
| **50088** | User exists, telecom MFA limit reached | `[*] Exists` / `Account State : MFA Telecom Call Limit Exceeded` |
| **65001** | Password valid, consent required | `[*] Exists` / `Password Status : Correct (Consent Required)` |

---

## [>] Installation

**Prerequisites:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/kavin-jindal/AZeus.git
cd AZeus

# Install requirements
pip install -r requirements.txt
```

---

## [*] Example Workflows

### 1. Passive Subdomain & Cloud Asset Mapping
```bash
python main.py -S contoso
```

### 2. Public Blob Container Discovery
```bash
python main.py -B contoso
```

### 3. Tenant Intelligence Gathering
```bash
python main.py -T contoso.com
```

### 4. Passive Username Enumeration & Security Profiling
```bash
python main.py -u user@contoso.com
```

### 5. Bulk Passive User Enumeration
```bash
python main.py -U wordlist.txt
```

### 6. Single Account Credential Validation
```bash
python main.py -u user@contoso.com -p "Password123!"
```

### 7. Userlist Password Spraying
```bash
python main.py -U users.txt -p "Autumn2024!"
```

### 8. Dictionary Password Spray Against Account
```bash
python main.py -u admin@contoso.com -P passlist.txt
```

---

## [!] License

Distributed under the MIT License. See `LICENSE` for more information.

<div align="center">

Crafted by **[Kavin Jindal](https://github.com/kavin-jindal)**

</div>
