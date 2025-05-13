import streamlit as st # type: ignore
import subprocess
import shutil
import socket
import os
import ipaddress
#from streamlit_autorefresh import st_autorefresh  # Das funktioniert auf dem Mac ganz gut

from script import (
    validatePrompt,
    sendPromptToFlask,
    createFile,
    extractRelevantContent,
    runDockerContainer,
    createHostOnlyNetwork,
    buildDockerImage
)
from utils import(
    saveTextToFile,
    loadTextFromFile,
    calculateGatewayIp,
    checkContainerExists,
    checkContainerStatus
)

# ---- Constants and Helpers -------------

FLASK_API_URL = "http://127.0.0.1:5000/honeyprompting"
OUTPUT_DIR = "output"
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
def saveTextToFile(filepath, content):
    with open(filepath, "w") as f:
        f.write(content)

def loadTextFromFile(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return f.read()
    return ""

def saveNetworkName(name):
    with open("saved_network.txt", "w") as f:
        f.write(name)

def loadNetworkName():
    if os.path.exists("saved_network.txt"):
        with open("saved_network.txt", "r") as f:
            return f.read().strip()
    return ""

def checkExistingGeneratedFiles():
    required_files = ["Dockerfile", "supervisord.conf", "setup_services.sh"]
    if not os.path.exists(OUTPUT_DIR):
        return None
    contents = {}
    for filename in required_files:
        path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            contents[filename] = f.read()
    return contents

def checkContainerStatus(container_name="honeypot_container"):
    try:
        result = subprocess.run(
            ["docker", "ps", "-f", f"name={container_name}", "--format", "{{.Status}}"],
            stdout=subprocess.PIPE,
            text=True
        )
        return "running" if result.stdout.strip() else "stopped"
    except Exception:
        return "unknown"

def resetProject():
    for f in ["saved_prompt.txt", "saved_ip.txt", "saved_network.txt"]:
        if os.path.exists(f):
            os.remove(f)
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    st.session_state.prompt = ""
    st.session_state.gpt_response = None
    st.session_state.custom_ip = "192.168.100.10"
    st.session_state.selected_network = ""

def check_container_exists(container_name):
    """Check if the container exists."""
    result = subprocess.run(
        ["docker", "ps", "-a", "-q", "-f", f"name={container_name}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout.strip()  # Returns container ID or empty string if not found

def calculate_gateway_ip(subnet):
    try:
        # Parse the subnet to get the network address
        network = ipaddress.IPv4Network(subnet, strict=False)
        # The gateway IP is typically the first usable IP address in the network
        gateway_ip = str(network.network_address + 1)
        return gateway_ip
    except ValueError as e:
        raise ValueError(f"Invalid subnet format: {e}")

# ----- Page Configuration -------------

st.set_page_config(page_title="Docker Honeypot Automation", layout="wide")
st.title("Prompt To Honeypot Tool")
#st_autorefresh(interval=10_000, key="refresh")

# Docker status badge
status = checkContainerStatus()
if status == "running":
    st.success("Container Status: Running")
elif status == "stopped":
    st.warning("Container Status: Stopped")
else:
    st.error("Container Status: Unknown")

# ------- Session State ------------

if "prompt" not in st.session_state:
    st.session_state.prompt = loadTextFromFile("saved_prompt.txt")
if "gpt_response" not in st.session_state:
    st.session_state.gpt_response = None
if "hostname" not in st.session_state:
    st.session_state.hostname = socket.gethostname()
if "custom_ip" not in st.session_state:
    ip = loadTextFromFile("saved_ip.txt")
    st.session_state.custom_ip = ip.strip() if ip else "192.168.100.10"
if "selected_network" not in st.session_state:
    st.session_state.selected_network = loadNetworkName()
if "system_message" not in st.session_state:
    st.session_state.system_message = DEFAULT_SYSTEM_MESSAGE

# ------- Sidebar -----------

menu = st.sidebar.radio("Navigation", ["Home", "Prompt & Generate", "Container Management", "Help"])
st.sidebar.markdown("---")
if st.sidebar.button("Reset Project"):
    resetProject()
    st.sidebar.success("Project reset! Refreshing...")
    st.rerun()

# ------- Home -----------

if menu == "Home":
    st.header("Welcome!")
    st.markdown(f"**Machine:** `{st.session_state.hostname}` | **Default IP:** `{st.session_state.custom_ip}`")

# ------ Prompt & Generate --------

if menu == "Prompt & Generate":
    with st.expander("Advanced: Customize LLM System Behavior (for experts)"):
        st.warning("Changing this prompt may break functionality. Proceed only if you know what you're doing.")
        system_message_input = st.text_area("System Prompt:", value=st.session_state.system_message, height=400)
        st.session_state.system_message = system_message_input

    st.header("Enter Your Honeypot Scenario")

    st.subheader("Set Custom Container IP")
    ip = st.text_input("Desired IP address:", value=st.session_state.custom_ip)
    if ip:
        st.session_state.custom_ip = ip.strip()
        saveTextToFile("saved_ip.txt", st.session_state.custom_ip)

    st.subheader("Write or Upload Prompt")
    uploaded_file = st.file_uploader("Upload a text prompt", type=["txt"])
    if uploaded_file:
        st.session_state.prompt = uploaded_file.read().decode("utf-8")

    with st.expander("How should the prompt look like?"):
        st.markdown("""
        ### Guidelines for Writing a Good Prompt:
        Clearly describe the type of vulnerable machine you want.
        Mention the context, business, or person using it
        You don't need to mention exact services (like Apache, SSH), the system will pick for you.
        Be as descriptive or imaginative as you want!
    
        ### Example of a Scenario:
        Autohaus Scherer is a trusted place to buy new Audi cars and get high-quality services like repairs, maintenance, financing, and trade-ins. Known for excellent customer care, convenient locations, and great offers, Autohaus Scherer makes every step of the car-buying process smooth and easy. The company cares about the environment and works hard to support the local community. With modern digital tools, virtual showrooms, and AI-powered suggestions, Autohaus Scherer provides a personalized experience for local buyers, luxury car fans, business clients, and others. Autohaus Scherer works closely with Audi and has strong partnerships with financing companies to bring the best value to its customers. Whether you need a car for everyday use or want a luxury vehicle, Autohaus Scherer offers top-quality service, innovative solutions, and a friendly approach to meet your needs.
        
        ### Example of a Prompt for this Scenario:
        provide a single container docker setup for the case described above imagine a Reciption Lady that stores and edits the data of all cutomers.
    
        ### Important:
        For one Scenario you may create many prompts
        You do not need technical knowledge about Docker or Linux.
        The machine is already primed as Network security expert, no need to say "Imagine you are..".
        Just describe what you want to simulate and in which context and possibly the role of a specific person.
        Mentioning "Create a Single Container Ddocker Setup" is important. 
        """)

    prompt = st.text_area("Or type your prompt here:", value=st.session_state.prompt, height=200)

    if st.button("Submit Prompt to GPT"):
        if validatePrompt(prompt):
            st.session_state.prompt = prompt
            saveTextToFile("saved_prompt.txt", prompt)
            with st.spinner("Sending prompt to Flask API..."):
                gpt_response = sendPromptToFlask(prompt, st.session_state.system_message)
                if gpt_response:
                    st.session_state.gpt_response = gpt_response
                    st.success("Prompt sent and response received!")
                else:
                    st.error("Failed to get a response.")
        else:
            st.warning("Prompt is invalid.")

    if st.session_state.gpt_response:
        st.subheader("Generated Files")
        extracted_files = extractRelevantContent(st.session_state.gpt_response)
        if extracted_files:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            for filename, content in extracted_files.items():
                st.subheader(f"{filename}")
                st.code(content, language="text")
                createFile(OUTPUT_DIR, filename, content)
            st.success("All files generated!")

            if st.button("Build Docker Image"):
                with st.spinner("Building Docker image..."):
                    try:
                        buildDockerImage(OUTPUT_DIR)
                        st.success("Docker image built successfully!")
                    except Exception as e:
                        st.error(f"Build failed: {e}")
        else:
            st.error("Extraction failed.")

    if not st.session_state.gpt_response:
        st.subheader("Detected Previously Generated Files")
        existing_files = checkExistingGeneratedFiles()
        if existing_files:
            for filename, content in existing_files.items():
                st.code(content, language="text")
            if st.button("Build Docker Image From Existing Files"):
                with st.spinner("Building Docker image..."):
                    try:
                        buildDockerImage(OUTPUT_DIR)
                        st.success("Docker image built successfully!")
                    except Exception as e:
                        st.error(f"Build failed: {e}")
        else:
            st.info("No previously generated files found.")

# ------ Container Management -----------

if menu == "Container Management":
    st.header("Manage Honeypot Container")

    st.info(f"Container IP: `{st.session_state.custom_ip}`")

    st.subheader("Network Configuration")
    network_mode = st.radio("Choose network mode:", ["Use existing network", "Create new network"])
    selected_network_name = None

    if network_mode == "Use existing network":
        try:
            result = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], stdout=subprocess.PIPE, text=True)
            networks = result.stdout.strip().split("\n")
            selected_network_name = st.selectbox("Select an existing network", networks, index=networks.index(st.session_state.selected_network) if st.session_state.selected_network in networks else 0)
            st.session_state.selected_network = selected_network_name
            saveNetworkName(selected_network_name)
        except Exception as e:
            st.error(f"Failed to list networks: {e}")

    if network_mode == "Create new network":
        with st.expander("Need help choosing subnet, gateway, or network name?"):
            st.markdown("""
        Tips for Choosing Network Settings:
    
        - Network Name: Can be anything like `honeynet`. Just make it unique.
        - Subnet: A private block like `192.168.200.0/24` is common.
        - Use `/24` for 256 addresses (192.168.200.1 - 192.168.200.254)
        - Avoid overlaps with your main LAN or VPN
        - Gateway: Should be the `.1` address in your subnet, like `192.168.200.1`
        """)
            
        with st.form("create_new_net_form"):
            net_name = st.text_input("Network name", value="honeynet")
            subnet = st.text_input("Subnet (CIDR)", value="192.168.200.0/24")
            
            if subnet:
                try:
                    gateway_ip = calculateGatewayIp(subnet)
                    st.text(f"Gateway IP: {gateway_ip}")
                except ValueError as e:
                    st.error(f"Error in subnet format: {e}")
            
            create_net = st.form_submit_button("Create Network")
            if create_net:
                if createHostOnlyNetwork(net_name, subnet, gateway_ip):
                    st.success(f"Network '{net_name}' created with gateway IP: {gateway_ip}.")
                    st.session_state.selected_network = net_name
                    saveNetworkName(net_name)
                    selected_network_name = net_name
                else:
                    st.error("Failed to create network.")

    st.subheader("Launch Container")
    user_ip = st.text_input("Container IP Address", value=st.session_state.custom_ip)

    if st.button("Run Container"):
        if not selected_network_name and st.session_state.selected_network:
            selected_network_name = st.session_state.selected_network
        if selected_network_name and user_ip:
            try:
                runDockerContainer(user_ip, selected_network_name)
                st.success(f"Container started on network: {selected_network_name} with IP: {user_ip}")
            except Exception as e:
                st.error(f"Failed to run container: {e}")
        else:
            st.warning("Please choose a network and IP.")

    st.subheader("Container Actions")
    col1, col2, col3, col4 = st.columns(4)
    container_name = "honeypot_container"

    with col1:
        if st.button("Stop Container"):
            container_id = checkContainerExists(container_name)
            if container_id:
                subprocess.run(["docker", "stop", container_id], stdout=subprocess.DEVNULL)
                st.success(f"Container '{container_name}' stopped.")
            else:
                st.warning(f"Container '{container_name}' does not exist.")

    with col2:
        if st.button("Remove Container"):
            container_id = checkContainerExists(container_name)
            if container_id:
                subprocess.run(["docker", "rm", container_id], stdout=subprocess.DEVNULL)
                st.success(f"Container '{container_name}' removed.")
            else:
                st.warning(f"Container '{container_name}' does not exist.")

    with col3:
        if st.button("Remove Image"):
            # Remove the image if it's not being used by any container
            subprocess.run(["docker", "rmi", "-f", "honeypot"], stdout=subprocess.DEVNULL)
            st.success("Image 'honeypot' removed.")

    with col4:
        if st.button("List Docker Networks"):
            result = subprocess.run(["docker", "network", "ls"], stdout=subprocess.PIPE, text=True)
            st.text(result.stdout)
