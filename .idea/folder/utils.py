import os
import subprocess
import ipaddress

def saveTextToFile(filepath, content):
    try:
        with open(filepath, "w") as f:
            f.write(content)
    except Exception as e:
        print(f"Error saving file {filepath}: {e}")

def loadTextFromFile(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                return f.read().strip()
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
    return ""

def checkContainerStatus(container_name="honeypot_container"):
    """Return 'running', 'stopped', or 'unknown'."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-f", f"name={container_name}", "--format", "{{.Status}}"],
            stdout=subprocess.PIPE,
            text=True
        )
        return "running" if result.stdout.strip() else "stopped"
    except Exception:
        return "unknown"

def checkContainerExists(container_name):
    """Return container ID if exists, else empty string."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "-q", "-f", f"name={container_name}"],
            stdout=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"Error checking container: {e}")
        return ""

def calculateGatewayIp(subnet):
    """Auto-derive gateway IP from subnet (e.g., 192.168.100.1 from 192.168.100.0/24)"""
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        return str(network.network_address + 1)
    except ValueError as e:
        raise ValueError(f"Invalid subnet format: {e}")
