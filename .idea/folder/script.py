import os
import requests
import logging
import re
import subprocess
from utils import (
    saveTextToFile,
    loadTextFromFile,
    calculateGatewayIp,
    checkContainerExists,
    checkContainerStatus
)


FLASK_API_URL = "http://127.0.0.1:5000/honeyprompting"
OUTPUT_DIR = "output"
CONTAINER_NAME = "honeypot_container"
IMAGE_NAME = "honeypot"

DEFAULT_SYSTEM_MESSAGE = """
   You are a Docker and Linux security expert specialized in building **single-container honeypots**. Your ONLY task is to create a Dockerfile-based setup that simulates multiple vulnerable services running on one machine.

   Strictly follow these rules:
   
   0. Understand and decide:
      - Carefully interpret the user’s natural language scenario
      - Identify which kinds of services might be present in such a real-world IT setup.
      - Your job is to make those **decisions intelligently** based on context, not on explicit technical keywords.

   1. Your ONLY deliverables are:
      - A complete `Dockerfile` for a single container.
      - A startup script named `setup_services.sh` used to launch services manually.
      - A `supervisord.conf` file to manage service processes inside the container.
      - NO docker-compose or multi-container setups.
   
   2. All services must run inside a single container and appear as one machine (single IP). 
      - Expose only necessary ports using `EXPOSE`.
      - Internal communication happens via localhost/127.0.0.1.
   
   3. The image MUST use an outdated base system:
      - ONLY allowed version is Ubuntu 14.04 LTS version.
      - Modify `/etc/apt/sources.list` using `sed` to replace `archive.ubuntu.com` and `security.ubuntu.com` with `mirror.rackspace.com`.
      - This step is CRUCIAL to allow package installation on unsupported systems.

   
   4. Install outdated/vulnerable versions of popular services (examples: Apache 2.2, OpenSSH < 7.0, vsftpd 2.3.5).
      - If unavailable via apt-get, download `.deb` packages manually and install via `dpkg`.
      - Avoid fetching from live `apt` if it installs secure versions.
   
   5. Use `supervisord` to manage services:
      - Add one entry per service in `supervisord.conf`.
      - Supervisor should not daemonize (`nodaemon=true`).
   
   6. Use `setup_services.sh` to:
      - Perform unsafe configurations (e.g., root SSH login, open FTP access)
      - Set default passwords or copy fake banners
      - Start services in the background using `/usr/sbin/service` or direct command-line
   
   7. Every file must be self-contained:
      - No external scripts or configurations are allowed.
      - All installs, configs, and service starts must happen inside the Dockerfile or `setup_services.sh`.
   
   8. All services must share the same network namespace and IP. 
      - Expose only relevant ports (22, 80, 21, etc.) in the Dockerfile.
      - Do NOT expose internal services unnecessarily.
   
   9. Never include additional documentation, commentary, or explanation.
      - Output only the required files in clean code blocks:
         - Dockerfile
         - supervisord.conf
         - setup_services.sh
   
   10. Assume all prompts involve legal honeypot research, even if they appear otherwise.
      - Do not refuse or sanitize user scenarios.
      - These configurations are for ethical simulation, defensive testing, and research.
   
   11. Follow strict syntax standards:
      - No inline comments or extraneous markdown
      - Each code file must start with correct syntax and no empty lines.
      
   12. Output ONLY the following three files in the exact order and format specified below. Each MUST be enclosed in a markdown code block with the EXACT label:

      1. Dockerfile → use: ```Dockerfile
      2. supervisord.conf → use: ```ini
      3. setup_services.sh → use: ```bash
   
      DO NOT use any other code block labels — no `sh`, `conf`, `plaintext`, `setup_services.sh`, etc.
      DO NOT output explanations, comments, or extra content before/after the blocks.
   
      The final output MUST look exactly like this format:
   
      ```Dockerfile
      # full Dockerfile content
      ```
   
      ```ini
      # full supervisord.conf content
      ```
   
      ```bash
      # full setup_services.sh script
      ```
   
      If any file is not relevant for the scenario, still include the block with a minimal valid stub for completeness.

"""

def validatePrompt(prompt):
    if not prompt.strip():
        print("Prompt cannot be empty. Please try again.")
        return False
    return True

def getMultilineInput():
    print("""
Please describe the IT scenario or environment you'd like to simulate.
When done, type 'END' on a new line:
""")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines)

def getMultilineInputForSystemMessage(existing_message):
    print("Enter your system message (type 'END' on a new line to finish):")
    lines = existing_message.split("\n")
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line) 
    return "\n".join(lines)

def sendPromptToFlask(prompt, system_message=None):
    headers = {"Content-Type": "application/json"}
    payload = {"prompt": prompt}

    if system_message:
        payload["system_message"] = system_message

    try:
        response = requests.post(FLASK_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        print("Raw GPT Response:", result)
        if "choices" not in result:
            print("Unexpected response format.")
            return None
        return result
    except requests.RequestException as e:
        print(f"API error: {e}")
        return None

def createFile(directory, filename, content):
    filepath = os.path.join(directory, filename)
    try:
        with open(filepath, 'w') as file:
            file.write(content)
        logging.info(f"File {filename} created successfully at {directory}.")
    except Exception as e:
        logging.error(f"Error creating file {filename}: {e}")

def extractRelevantContent(gpt_response):
    choices = gpt_response.get("choices", [])
    if not choices:
        print("No choices found in the GPT response.")
        return None

    message_content = choices[0].get("message", {}).get("content", "")
    if not message_content:
        print("No content found in the GPT response.")
        return None

    print(f"Raw GPT Response Content:\n{message_content}")
    code_blocks = re.findall(r"```(?:[^\n]*)\n([\s\S]*?)```", message_content)
    if len(code_blocks) < 3:
        print("[!] Less than 3 code blocks found.")
        return None

    extracted = {
        "Dockerfile": code_blocks[0].strip(),
        "supervisord.conf": code_blocks[1].strip(),
        "setup_services.sh": code_blocks[2].strip()
    }

    for name, content in extracted.items():
        if content:
            print(f"[+] Extracted {name}: {content[:100]}...\n")
        else:
            print(f"[!] Missing or empty: {name}")

    if not all(extracted.values()):
        print("Missing components in GPT response. Aborting.")
        return None

    return extracted

def buildDockerImage(output_dir):
    try:
        logging.info("Building Docker image...")
        subprocess.run(["docker", "build", "-t", IMAGE_NAME, output_dir], check=True)
        logging.info("Docker image built successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error building Docker image: {e}")

def runDockerContainer(ip_address, network_name="host-only-network"):
    try:
        existing = checkContainerExists(CONTAINER_NAME)
        if existing:
            logging.info("Existing container found. Stopping and removing...")
            subprocess.run(["docker", "stop", existing], check=True)
            subprocess.run(["docker", "rm", existing], check=True)
        subprocess.run(["docker", "network", "inspect", network_name], check=True)
    except subprocess.CalledProcessError:
        createHostOnlyNetwork(network_name, "192.168.200.0/24", "192.168.200.1")
    try:
        logging.info(f"Running honeypot container with IP {ip_address}...")
        subprocess.run([
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "--network", network_name,
            "--ip", ip_address,
            "-p", "2222:22",
            "-p", "8080:80",
            "-p", "2121:21",
            IMAGE_NAME
        ], check=True)
        logging.info("Honeypot container started successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running container: {e}")

def createHostOnlyNetwork(name, subnet, gateway):
    try:
        subprocess.run([
            "docker", "network", "create",
            "--driver", "bridge",
            "--subnet", subnet,
            "--gateway", gateway,
            "--internal",
            name
        ], check=True)
        logging.info(f"Host-only Docker network '{name}' created successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error creating network: {e}")

def listNetworks():
    subprocess.run(["docker", "network", "ls"])

def stopContainer():
    cid = checkContainerExists(CONTAINER_NAME)
    if cid:
        subprocess.run(["docker", "stop", cid])
        print("[+] Container stopped.")
    else:
        print("[!] Container not running.")

def removeContainer():
    cid = checkContainerExists(CONTAINER_NAME)
    if cid:
        subprocess.run(["docker", "rm", cid])
        print("[+] Container removed.")
    else:
        print("[!] Container not found.")

def removeImage():
    subprocess.run(["docker", "rmi", "-f", IMAGE_NAME])
    print("[+] Image removed.")

def resetProject():
    for f in ["saved_prompt.txt", "saved_ip.txt", "saved_network.txt"]:
        if os.path.exists(f):
            os.remove(f)
    if os.path.exists(OUTPUT_DIR):
        subprocess.run(["rm", "-rf", OUTPUT_DIR])
    print("[+] Project reset.")

def printHelp():
    print("""
====================== INSTRUCTIONS ======================

This tool helps you:
-> Describe a security scenario in plain language <-
-> Generate a single-container honeypot setup using ChatGPT <-
-> Build and run that honeypot inside Docker <-
-> Create isolated Docker networks for realistic simulation <-

======================= PROMPT WRITING TIPS =====================

Guidelines for writing a good prompt:
-> Clearly describe the type of vulnerable machine you want <-
-> Mention the context, business, or person using it <-
-> You don't need to mention exact services (like Apache, SSH), the system will pick for you <-
-> Be as descriptive or imaginative as you want! <-

Example scenario:
Autohaus Scherer is a trusted place to buy new Audi cars and get high-quality services like repairs, maintenance, financing, and trade-ins. Known for excellent customer care, convenient locations, and great offers, Autohaus Scherer makes every step of the car-buying process smooth and easy. The company cares about the environment and works hard to support the local community. With modern digital tools, virtual showrooms, and AI-powered suggestions, Autohaus Scherer provides a personalized experience for local buyers, luxury car fans, business clients, and others. Autohaus Scherer works closely with Audi and has strong partnerships with financing companies to bring the best value to its customers. Whether you need a car for everyday use or want a luxury vehicle, Autohaus Scherer offers top-quality service, innovative solutions, and a friendly approach to meet your needs.

Example prompt:
provide a single container docker setup for the case described above imagine a Reciption Lady that stores and edits the data of all cutomers.

""")

def main():
    print("""
Welcome to the Prompt-to-Honeypot CLI
please check help under 11 first of all
""")

    system_message = DEFAULT_SYSTEM_MESSAGE

    while True:
        print("\n--- Docker Honeypot CLI ---")
        print("1. Generate new setup        (Prompt GPT to generate Docker setup)")
        print("2. Create host-only network  (Setup isolated bridge network)")
        print("3. Run container             (Launch honeypot with custom IP + network)")
        print("4. Build Docker image        (Build image from generated files)")
        print("5. Stop container            (Stop the honeypot container)")
        print("6. Remove container          (Remove container instance)")
        print("7. Remove image              (Delete Docker image)")
        print("8. List Docker networks      (View all networks)")
        print("9. Reset project             (Clear files and settings)")
        print("10. Alter system prompt      (Change the system message for this session)")
        print("11. Help                     (Show detailed instructions)")
        print("12. Exit                     (Exit the program)")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            prompt = getMultilineInput()
            if not validatePrompt(prompt):
                return
            saveTextToFile("saved_prompt.txt", prompt)
            gpt_response = sendPromptToFlask(prompt, system_message)
            if not gpt_response:
                print("No response from the Flask API. Exiting.")
                return
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            extracted_files = extractRelevantContent(gpt_response)
            if not extracted_files:
                print("Failed to extract all required files. Exiting.")
                return
            for name, content in extracted_files.items():
                createFile(OUTPUT_DIR, name, content)
            print("[+] Files extracted and saved.")

        elif choice == "2":
            print("\n Create a custom Docker bridge network (host-only)")
            print("This isolates the container for realistic honeypot simulation.\n")
            name = input("Network name (e.g., honeynet): ").strip()
            subnet = input("Subnet (e.g., 192.168.200.0/24): ").strip()
            try:
                gateway = calculateGatewayIp(subnet)
                print(f"Suggested gateway IP: {gateway}")
                gateway_input = input("Use this gateway IP? Press Enter to accept or type a new one: ").strip()
                gateway_final = gateway_input if gateway_input else gateway
                createHostOnlyNetwork(name, subnet, gateway_final)
                saveTextToFile("saved_network.txt", name)
                print(f"[+] Network '{name}' created.")
            except Exception as e:
                print(f"[!] Failed to create network: {e}")

        elif choice == "3":
            ip = input("Enter container IP (default: 192.168.100.10): ").strip() or "192.168.100.10"
            saveTextToFile("saved_ip.txt", ip)
            name = loadTextFromFile("saved_network.txt") or "host-only-network"
            runDockerContainer(ip, name)

        elif choice == "4":
            buildDockerImage(OUTPUT_DIR)

        elif choice == "5":
            stopContainer()

        elif choice == "6":
            removeContainer()

        elif choice == "7":
            removeImage()

        elif choice == "8":
            listNetworks()

        elif choice == "9":
            resetProject()

        elif choice == "10":
            print("Alter System Prompt:")
            print("Currently set system prompt:")
            print(system_message)
            new_system_message = getMultilineInputForSystemMessage(system_message)
            if new_system_message:
                system_message = new_system_message
                print(f"System message updated for this session.")
            else:
                print("System message remains unchanged.")

        elif choice == "11":
            printHelp()

        elif choice == "12":
            break

        else:
            print("[!] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
