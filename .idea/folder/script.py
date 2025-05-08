import os
import requests
import logging
import re
import subprocess
from utils import (
    save_text_to_file,
    load_text_from_file,
    calculate_gateway_ip,
    check_container_exists,
    check_container_status
)

FLASK_API_URL = "http://127.0.0.1:5000/honeyprompting"
OUTPUT_DIR = "output"
CONTAINER_NAME = "honeypot_container"
IMAGE_NAME = "honeypot"

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

def sendPromptToFlask(prompt):
    headers = {"Content-Type": "application/json"}
    payload = {"prompt": prompt}
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
        existing = check_container_exists(CONTAINER_NAME)
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

def list_networks():
    subprocess.run(["docker", "network", "ls"])

def stop_container():
    cid = check_container_exists(CONTAINER_NAME)
    if cid:
        subprocess.run(["docker", "stop", cid])
        print("[+] Container stopped.")
    else:
        print("[!] Container not running.")

def remove_container():
    cid = check_container_exists(CONTAINER_NAME)
    if cid:
        subprocess.run(["docker", "rm", cid])
        print("[+] Container removed.")
    else:
        print("[!] Container not found.")

def remove_image():
    subprocess.run(["docker", "rmi", "-f", IMAGE_NAME])
    print("[+] Image removed.")

def reset_project():
    for f in ["saved_prompt.txt", "saved_ip.txt", "saved_network.txt"]:
        if os.path.exists(f):
            os.remove(f)
    if os.path.exists(OUTPUT_DIR):
        subprocess.run(["rm", "-rf", OUTPUT_DIR])
    print("[+] Project reset.")

def print_help():
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
        print("10. Exit")
        print("11. Help                     (Show detailed instructions)")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            prompt = getMultilineInput()
            if not validatePrompt(prompt):
                return
            save_text_to_file("saved_prompt.txt", prompt)
            gpt_response = sendPromptToFlask(prompt)
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
                gateway = calculate_gateway_ip(subnet)
                print(f"Suggested gateway IP: {gateway}")
                gateway_input = input("Use this gateway IP? Press Enter to accept or type a new one: ").strip()
                gateway_final = gateway_input if gateway_input else gateway
                createHostOnlyNetwork(name, subnet, gateway_final)
                save_text_to_file("saved_network.txt", name)
                print(f"[+] Network '{name}' created.")
            except Exception as e:
                print(f"[!] Failed to create network: {e}")

        elif choice == "3":
            ip = input("Enter container IP (default: 192.168.100.10): ").strip() or "192.168.100.10"
            save_text_to_file("saved_ip.txt", ip)
            name = load_text_from_file("saved_network.txt") or "host-only-network"
            runDockerContainer(ip, name)

        elif choice == "4":
            buildDockerImage(OUTPUT_DIR)

        elif choice == "5":
            stop_container()

        elif choice == "6":
            remove_container()

        elif choice == "7":
            remove_image()

        elif choice == "8":
            list_networks()

        elif choice == "9":
            reset_project()

        elif choice == "10":
            break

        elif choice == "11":
            print_help()

        else:
            print("[!] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
