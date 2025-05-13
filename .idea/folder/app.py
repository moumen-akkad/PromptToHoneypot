from flask import Flask, request, jsonify
import requests
import os


GPT_API_URL = "https://api.openai.com/v1/chat/completions"

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024



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
@app.route("/honeyprompting", methods=["POST"])
def honeyprompting():

    try:
        data = request.json
        prompt = data.get("prompt")
        custom_system_message = data.get("system_message")

        if not prompt:
            return jsonify({"error": "Prompt is required"}), 400
        
        system_message = custom_system_message or DEFAULT_SYSTEM_MESSAGE

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "chatgpt-4o-latest",
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 1000,
            "temperature": 0.9,
        }

        response = requests.post(GPT_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        return jsonify(response.json())

    except requests.RequestException as e:
        error_message = f"OpenAI API request failed: {str(e)}"
        print(error_message)  # Log it for debugging
        return jsonify({"error": error_message}), 500
if __name__ == "__main__":
    app.run(debug=True)
