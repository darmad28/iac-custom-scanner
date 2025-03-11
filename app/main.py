from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
from typing import List, Optional
import json

app = FastAPI()

# --- Anti-DDoS Security Constants ---

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB limit
MAX_JSON_DEPTH = 10  # Maximum allowed depth for JSON

# --- Pydantic MODELS ---

class KubernetesResourceModel(BaseModel):
    apiVersion: str
    kind: str
    metadata: dict
    spec: dict


class IaCResourceModel(BaseModel):
    type: str
    name: str
    open_ports: Optional[List[int]] = []
    password: Optional[str] = None
    encryption: Optional[bool] = None
    mfa_enabled: Optional[bool] = None
    azure_specific: Optional[dict] = None


class IaCModel(BaseModel):
    resources: list[IaCResourceModel]


# --- Anti-DDoS (JSON depth) Security Enhancement ---

def check_json_depth(data, max_depth=MAX_JSON_DEPTH, current_depth=0):
    """Prevent deeply nested JSON structures"""
    if current_depth > max_depth:
        raise ValueError("JSON structure too deeply nested.")

    if isinstance(data, dict):
        for value in data.values():
            check_json_depth(value, max_depth, current_depth + 1)
    elif isinstance(data, list):
        for item in data:
            check_json_depth(item, max_depth, current_depth + 1)

# --- ANALYSIS FUNCTIONS ---

def analyze_kubernetes_security(config_json):
    """Analyze security vulnerabilities in Kubernetes manifest"""
    vulnerabilities = []

    namespace = config_json.get("metadata", {}).get("namespace", "")
    if namespace == "default":
        vulnerabilities.append({
            "issue": "Using 'default' namespace",
            "severity": "MEDIUM",
            "explanation": "Using the 'default' namespace can lead to segregation and security issues.",
            "remediation": "Use a specific namespace for each application and apply RBAC controls."
        })

        # Locate containers in different structures
    container_paths = [
        config_json.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []),  # Knative & Deployments
        config_json.get("spec", {}).get("containers", []),  # Pods
        config_json.get("podSpec", {}).get("containers", [])  # DaemonSets, StatefulSets
    ]

    # Find the first valid list of containers
    containers = next((c for c in container_paths if c), [])

    for container in containers:
        env_vars = container.get("env", [])
        for env_var in env_vars:
            if "SECRET" in env_var["name"].upper() or "PASSWORD" in env_var["name"].upper():
                vulnerabilities.append({
                    "issue": f"Secret exposed in environment variable: {env_var['name']}",
                    "severity": "HIGH",
                    "explanation": "Credentials should not be stored in environment variables as they may be leaked in logs or extracted by attackers.",
                    "remediation": "Use a secret manager like AWS Secrets Manager, HashiCorp Vault, or Kubernetes Secrets."
                })
            elif "PUBLIC_BUCKET" in env_var["name"].upper() or "http://public-bucket" in env_var.get("value", ""):
                vulnerabilities.append({
                    "issue": f"Storage bucket publicly exposed: {env_var['value']}",
                    "severity": "HIGH",
                    "explanation": "Exposing buckets publicly may allow unauthorized access to sensitive data.",
                    "remediation": "Configure restrictive IAM policies and avoid public access to sensitive data."
                })

        security_context = container.get("securityContext", {})
        if security_context.get("runAsUser", 1) == 0 or security_context.get("privileged", False):
            vulnerabilities.append({
                "issue": "Container running with elevated privileges or as root",
                "severity": "HIGH",
                "explanation": "Running a container as root increases the risk of privilege escalation in case of exploitation.",
                "remediation": "Set 'runAsUser' with a non-root UID and avoid privileged mode in containers."
            })

    # Format the results
    result = ""
    for vuln in vulnerabilities:
        result += f"**Issue**: {vuln['issue']}\n**Severity**: {vuln['severity']}\n**Explanation**: {vuln['explanation']}\n**Remediation**: {vuln['remediation']}\n\n"

    return result


def analyze_iac_security(config_json):
    """Analyze security vulnerabilities in Infrastructure as Code (IaC)"""
    vulnerabilities = []
    # Classify IaC resources by type
    for resource in config_json.get("resources", []):
        res_type = resource["type"]
        name = resource["name"]

        # IaC Security Policies for Virtual Machines
        if res_type == "virtual_machine":
            open_ports = resource.get("open_ports", [])
            for open_port in open_ports:
                if open_port == 22:
                    vulnerabilities.append({
                        "issue": f"Virtual machine '{name}' has port TCP 22 (SSH) open.",
                        "severity": "HIGH",
                        "explanation": "TCP port 22 (SSH - management port for Linux machines) is open to the Internet.",
                        "remediation": f"Check firewall rules (security groups) assigned to {name} subnet and limit port 22 access. Use a VPN, bastion host or Identity Access Policies instead of exposing SSH publicly."
                    })

                elif open_port == 3389:
                    vulnerabilities.append({
                        "issue": f"Virtual machine '{name}' has port TCP 3389 (RDP) open.",
                        "severity": "HIGH",
                        "explanation": "TCP port 3389 (RDP - management port for Windows machines) is open to the Internet.",
                        "remediation": f"Check firewall rules (security groups) assigned to {name} subnet and limit port 3389 access. Use a VPN, bastion host or Identity Access Policies instead of exposing RDP publicly."
                    })

            if isinstance(resource.get("password"), str):
                vulnerabilities.append({
                    "issue": f"Resource '{name}' exposes a plaintext password.",
                    "severity": "CRITICAL",
                    "explanation": "Storing passwords in plaintext inside IaC templates exposes sensitive credentials.",
                    "remediation": "Use a secrets manager (e.g., AWS/GCP Secrets Manager, Azure Key Vault) instead of hardcoding passwords."
                })

            if len(resource.get("password", "")) < 16:
                vulnerabilities.append({
                    "issue": f"Virtual machine '{name}' uses a weak password.",
                    "severity": "HIGH",
                    "explanation": "A weak password can be easily guessed or cracked, which increases the risk of unauthorized access.",
                    "remediation": "Use secure passwords with at least 16 characters, including uppercase, numbers, and symbols."
                })

            if not resource.get("encryption", False):
                vulnerabilities.append({
                    "issue": f"Virtual machine '{name}' does not have encryption enabled.",
                    "severity": "MEDIUM",
                    "explanation": "Unencrypted data may be vulnerable in case of unauthorized access.",
                    "remediation": "Enable encryption at rest to protect the data. For virtual machines you should encrypt data volumes (disks) attached to the instance."
                })

            if not resource.get("mfa_enabled", False):
                vulnerabilities.append({
                    "issue": f"Users with access to Virtual Machine '{name}' do not have multi-factor authentication (MFA) enabled.",
                    "severity": "HIGH",
                    "explanation": "Lack of MFA makes it easier for unauthorized access in case of credential leakage.",
                    "remediation": "Enable MFA for all accounts with critical access."
                })

        # IaC Security Policies for Storage Accounts
        elif res_type == "storage_account":
            if not resource.get("encryption", False):
                vulnerabilities.append({
                    "issue": f"Storage account '{name}' does not have encryption enabled.",
                    "severity": "HIGH",
                    "explanation": "Unencrypted data may be vulnerable in case of unauthorized access.",
                    "remediation": "Enable encryption at rest to protect the data."
                })

            if resource.get("azure_specific", {}).get("replication") == "LRS":
                vulnerabilities.append({
                    "issue": f"Storage account '{name}' use Locally Redundant Storage (LRS).",
                    "severity": "MEDIUM",
                    "explanation": "LRS is not the best option to avoid data loss or service disruption in case of regional failures",
                    "remediation": "Use ZRS/GRS replication for production environments to ensure high availability and data durability."
                })

        # IaC Security Policies for Databases
        elif res_type == "database":
            open_ports = resource.get("open_ports", [])
            insecure_ports = [1433, 3306, 5432, 1521, 27017, 6379, 9042]  # MSSQL,MySQL,PostgreSQL,Oracle,MongoDB,Redis,Cassandra
            for port in open_ports:
                if port in insecure_ports:
                    vulnerabilities.append({
                        "issue": f"Database '{name}' has an open insecure port {port}.",
                        "severity": "HIGH",
                        "explanation": "This port is commonly used by database services and could be vulnerable to unauthorized access if exposed.",
                        "remediation": "Close the port or restrict access to trusted IPs. Use VPN or secure tunnels for remote access."
                    })

            password = resource.get("password", "")
            if isinstance(password, str):
                vulnerabilities.append({
                    "issue": f"Resource '{name}' exposes a plaintext password.",
                    "severity": "CRITICAL",
                    "explanation": "Storing passwords in plaintext inside IaC templates exposes sensitive credentials.",
                    "remediation": "Use a secrets manager (e.g., AWS/GCP Secrets Manager, Azure Key Vault) instead of hardcoding passwords."
                })

            if len(password) < 16:
                vulnerabilities.append({
                    "issue": f"Database '{name}' has a weak password.",
                    "severity": "HIGH",
                    "explanation": "A weak password can be easily guessed or cracked, which increases the risk of unauthorized access.",
                    "remediation": "Ensure that passwords are at least 16 characters long and contain a combination of letters, numbers, and special characters."
                })

            if not resource.get("encryption", False):
                vulnerabilities.append({
                    "issue": f"Database '{name}' does not have encryption enabled.",
                    "severity": "MEDIUM",
                    "explanation": "Unencrypted databases are vulnerable to data breaches in case of unauthorized access.",
                    "remediation": "Enable encryption to protect the database and sensitive data."
                })

            if not resource.get("mfa_enabled", True):
                vulnerabilities.append({
                    "issue": f"Database '{name}' does not have multi-factor authentication (MFA) enabled.",
                    "severity": "HIGH",
                    "explanation": "Lack of MFA makes it easier for unauthorized access in case of credential leakage.",
                    "remediation": "Enable MFA for all accounts with privileged access to the database."
                })

    # Format de results
    result = ""
    for vuln in vulnerabilities:
        result += f"**Issue**: {vuln['issue']}\n**Severity**: {vuln['severity']}\n**Explanation**: {vuln['explanation']}\n**Remediation**: {vuln['remediation']}\n\n"

    return result


# --- ENDPOINT ---
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    """Security validation process: check file type"""
    if file.content_type != "application/json":
        raise HTTPException(status_code=400, detail="Only JSON files are allowed.")

    # Security validation process: check file length
    try:
        content = await file.read()

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large. Maximum allowed size is 2MB.")

        # Security validation process: check file depth
        json_data = json.loads(content)
        check_json_depth(json_data)

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Detect the type of JSON and apply the appropriate analysis
    try:
        validated_kubernetes = KubernetesResourceModel(**json_data)
        return PlainTextResponse(analyze_kubernetes_security(validated_kubernetes.dict()))
    except ValidationError:
        pass

    try:
        validated_iac = IaCModel(**json_data)
        return PlainTextResponse(analyze_iac_security(validated_iac.dict()))
    except ValidationError:
        pass

    # Security validation process: JSON structure not valid
    raise HTTPException(status_code=400, detail="The file does not contain a valid structure for Kubernetes or IaC JSON.")
