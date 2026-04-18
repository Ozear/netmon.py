# netmon.py
This Python script is a Cybersecurity Network Monitor designed to hunt for Indicators of Compromise (IOCs) on your machine. It takes a snapshot of all active network connections, identifies the processes responsible for them, and enriches that data with geographic IP information and basic threat heuristics.


# 🛡️ Security Netmon: Cybersecurity Network Monitor

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org/)

I used to rely heavily on standard tools like `netstat` to get a quick pulse on what my machines were doing. But honestly, modern operating systems run so many background processes that filtering through the noise to inspect individual connections has become a huge headache.

I built **Security Netmon** to fix that. It’s a straightforward script that gives you a clear, actionable look at your system's network activity. Think of it as a modern, context-rich upgrade to `netstat` that does the heavy lifting for you.

*(Note: The foundational code for this project was written with AI assistance to help quickly prototype a better network triage tool.)*

---

## ✨ Features

* **Real-Time Process Mapping:** Instantly links active network connections to their parent processes (PID, Name, and Executable Path). No more guessing what background app is phoning home.
* **Automated File Hashing:** Calculates SHA-256 hashes of running executables on the fly. This makes it super easy to cross-reference files against Threat Intelligence feeds like VirusTotal.
* **Heuristic IOC Detection:** Automatically flags sketchy behavior, like connections over known Command & Control ports (e.g., `4444`, `1337`) or programs running from weird directories (like `AppData` or `Temp`).
* **Enriched Context:** Caches IP geolocation, WHOIS data, and reverse DNS information to give you deep context on remote servers without spamming APIs.
* **Clean Terminal UI:** Displays a highly readable, color-coded table right in your terminal.
* **Automated Export:** Saves all the data it collects—including risk flags—into a structured CSV file so you can analyze it later.

---

## ⚙️ Prerequisites & Installation

You'll need Python 3.7+ and administrative privileges (`root`/`sudo` or Run as Administrator) to let the script properly inspect system-level processes.

### Windows Installation

1. **Install Python:** Grab the latest installer from the official Python website. **Crucial step:** Make sure to check the **"Add Python to PATH"** box during installation.
2. **Open your Terminal:** Fire up Command Prompt or PowerShell as an Administrator.
3. **Install Dependencies:** Run this command to grab the required libraries:
   ```cmd
   pip install psutil requests rich ipwhois
   ```

### Linux Installation (Ubuntu/Debian)

Because modern Linux distros enforce PEP 668, you can't just globally `pip install` without hitting an `externally-managed-environment` error. Pick one of the methods below to set up the dependencies (`psutil`, `requests`, `rich`, `ipwhois`):

#### Method 1: Virtual Environment (🌟 Recommended)
This keeps everything isolated and won't mess with your OS packages.

1. **Install venv:**
   ```bash
   sudo apt update
   sudo apt install python3-venv
   ```
2. **Create the environment** (run this inside your script's folder):
   ```bash
   python3 -m venv sec_env
   ```
3. **Activate and install:**
   ```bash
   source sec_env/bin/activate
   pip install psutil requests rich ipwhois
   ```

#### Method 2: Global Override (⚠️ Use with Caution)
If you really don't want to use virtual environments, you can force the installation system-wide. *Note: This can occasionally break OS-level Python tools, so only do this if you know what you're doing.*
```bash
sudo pip install psutil requests rich ipwhois --break-system-packages
```

---

## 🚀 Usage

To get actual value out of SecNetMon, you **must** run it as an Administrator or Root. If you don't, the script won't have the permissions to read file paths or hash system processes, and you'll just get a bunch of "Access Denied" errors.

### Running the Script

**If you used Linux Method 1 (Virtual Environment):**
Because `sudo` resets your terminal environment, you have to point it directly to the Python executable inside your newly created virtual environment folder:
```bash
sudo ./sec_env/bin/python netmon_security.py
```

**If you used Linux Method 2 (Global Override) or are on Windows:**
Just run it normally (but elevated):
```bash
# Linux
sudo python3 netmon_security.py

# Windows (Make sure your terminal is running as Administrator)
python netmon_security.py
```

### Command Line Options

You can tweak how the script runs using a couple of flags:

| Flag | Short | What it does | Default |
| :--- | :--- | :--- | :--- |
| `--time` | `-t` | How long to monitor the network (in seconds). | 15 |
| `--output` | `-o` | The name of the CSV file it saves. | `netmon_iocs.csv` |

**Example:** Monitor for a full minute and save the results to a custom file:
```bash
sudo ./sec_env/bin/python netmon_security.py --time 60 --output my_capture.csv
```

---

## 🔍 Under the Hood: What Happens When You Run It?

Once you start the script, here is exactly what it does:

1. **Privilege Check:** It verifies if it has Admin/Root rights. If it doesn't, it'll warn you and pause for a couple of seconds so you know you're flying blind on certain processes.
2. **Monitoring Loop:** It kicks off a loop that runs for 15 seconds (or whatever time you set). Every single second, it takes a snapshot of your active internet connections.
3. **Data Gathering:** For every connection, it grabs the Process ID (PID), the app's name (like `firefox.exe`), exactly where the executable is located on your hard drive, a SHA256 hash of the file, and all the local/remote IP details.
4. **Network Enrichment:** When it sees a remote IP, it does a quick reverse DNS lookup and asks `ip-api.com` who owns the IP. This gives you the country, the ISP/Organization, and the server's hostname.
5. **Risk Analysis:** It runs all this data through a lightweight heuristics engine. It flags suspicious stuff—like executables hiding in your `AppData` or `Temp` folders, traffic hitting common malware ports, or impostor files (e.g., something calling itself `svchost.exe` but running from your Downloads folder). It then scores the connection as "LOW", "MED", or "HIGH" risk.
6. **Reporting:** When the timer is up (or if you hit `Ctrl+C`), it prints everything out nicely and dumps the raw data to a CSV.

---

## 📊 Expected Output

### 1. Terminal Output
You will get a beautifully formatted, color-coded table printed right in your console. The columns include:

* **Risk:** Color-coded threat levels (Red = HIGH, Yellow = MED, Green = LOW).
* **Process:** The name of the app making the connection.
* **PID:** The process ID.
* **Full Path:** Exactly where the executable lives.
* **Remote Addr:** The destination IP, Port, and Hostname.
* **Geo/Org:** The country and organization hosting the server.
* **SHA256 (Truncated):** The first 12 characters of the file's hash (the full hash goes to the CSV).

### 2. CSV Output
By default, it drops a file named `netmon_iocs.csv` into your current folder. This file holds the complete, untruncated dataset for every unique connection it saw. You'll find timestamps, user accounts, full SHA256 hashes, and specific risk flags (like "SUSPICIOUS_PATH") inside.

---

## ⚠️ Disclaimer

I built this for educational and defensive purposes. Keep in mind that network monitors can capture sensitive system data. Make sure you have explicit permission to run this on any network or machine you deploy it to. I am not responsible for any misuse or damage caused by this software.

## 📄 License

This project is released into the Public Domain via The Unlicense.

You are completely free to use, modify, distribute, or sell this software without any restrictions. Attribution is nice, but totally optional. Check the `LICENSE` file for the legal specifics.
