from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
import json

app = FastAPI()


# --- Pydantic MODELS ---

class KnativeConfigModel(BaseModel):
    apiVersion: str
    kind: str
    metadata: dict
    spec: dict


class IaCResourceModel(BaseModel):
    type: str
    name: str
    azure_specific: dict



class IaCModel(BaseModel):
    resources: list[IaCResourceModel]


# --- ANALYSIS FUNCTIONS ---

def analyze_knative_security(config_json):
    """Analyze security vulnerabilities in Knative"""
    vulnerabilities = []

    namespace = config_json.get("metadata", {}).get("namespace", "")
    if namespace == "default":
        vulnerabilities.append({
            "issue": "Using 'default' namespace",
            "severity": "MEDIUM",
            "explanation": "Using the 'default' namespace can lead to segregation and security issues.",
            "remediation": "Use a specific namespace for each application and apply RBAC controls."
        })

    env_vars = config_json.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])[0].get("env", [])
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

    security_context = config_json.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])[0].get(
        "securityContext", {})
    if security_context.get("runAsUser", 1) == 0 or security_context.get("privileged", False):
        vulnerabilities.append({
            "issue": "Container running with elevated privileges or as root",
            "severity": "HIGH",
            "explanation": "Running a container as root increases the risk of privilege escalation in case of exploitation.",
            "remediation": "Set 'runAsUser' with a non-root UID and avoid privileged mode in containers."
        })

    result = ""
    for vuln in vulnerabilities:
        result += f"**Issue**: {vuln['issue']}\n**Severity**: {vuln['severity']}\n**Explanation**: {vuln['explanation']}\n**Remediation**: {vuln['remediation']}\n\n"

    return result


def analyze_iac_security(config_json):
    """Analyze security vulnerabilities in Infrastructure as Code (IaC)"""
    vulnerabilities = []

    for resource in config_json.get("resources", []):
        res_type = resource["type"]
        name = resource["name"]

        if res_type == "virtual_machine":
            open_ports = resource.get("open_ports", [])
            if 22 in open_ports:
                vulnerabilities.append({
                    "issue": f"Virtual machine '{name}' has port 22 open.",
                    "severity": "HIGH",
                    "explanation": "Port 22 (SSH) is a common target for brute force attacks.",
                    "remediation": "Use a VPN or bastion host instead of exposing SSH publicly."
                })

            if len(resource.get("password", "")) < 12:
                vulnerabilities.append({
                    "issue": f"Virtual machine '{name}' uses a weak password.",
                    "severity": "HIGH",
                    "explanation": "Short passwords are vulnerable to brute force attacks.",
                    "remediation": "Use secure passwords with at least 12 characters, including uppercase, numbers, and symbols."
                })

        elif res_type == "storage_account":
            if not resource.get("encryption", False):
                vulnerabilities.append({
                    "issue": f"Storage account '{name}' does not have encryption enabled.",
                    "severity": "MEDIUM",
                    "explanation": "Unencrypted data may be vulnerable in case of unauthorized access.",
                    "remediation": "Enable encryption at rest to protect the data."
                })

        elif res_type == "database":
            if not resource.get("mfa_enabled", True):
                vulnerabilities.append({
                    "issue": f"Database '{name}' does not have multi-factor authentication (MFA) enabled.",
                    "severity": "HIGH",
                    "explanation": "Lack of MFA makes it easier for unauthorized access in case of credential leakage.",
                    "remediation": "Enable MFA for all accounts with critical access."
                })

    result = ""
    for vuln in vulnerabilities:
        result += f"**Issue**: {vuln['issue']}\n**Severity**: {vuln['severity']}\n**Explanation**: {vuln['explanation']}\n**Remediation**: {vuln['remediation']}\n\n"

    return result


# --- ENDPOINT ---

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """Detect the type of JSON and apply the appropriate analysis."""

    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only JSON files are allowed.")

    try:
        content = json.loads(file.file.read().decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="The file does not contain valid JSON.")

    try:
        validated_knative = KnativeConfigModel(**content)
        result = analyze_knative_security(validated_knative.dict())
        return PlainTextResponse(result)
    except ValidationError:
        pass

    try:
        validated_iac = IaCModel(**content)
        result = analyze_iac_security(validated_iac.dict())
        return PlainTextResponse(result)
    except ValidationError:
        pass

    raise HTTPException(status_code=400,
                        detail="The file does not contain a valid structure for Knative or Infrastructure as Code JSON.")
