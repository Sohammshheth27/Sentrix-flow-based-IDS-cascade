# Installation

## System requirements

- Linux (Ubuntu 22.04 LTS or newer recommended)
- Python 3.12+
- 8 GB RAM, 2 CPU cores minimum
- A SPAN/mirror port on the network switch feeding the Sentrix host

## Steps

1. Clone the repository.
2. Create a Python virtualenv: `python3 -m venv venv && source venv/bin/activate`.
3. Install dependencies: `pip install -r requirements.txt`.
4. Install Zeek and Suricata via the OS package manager.
5. Configure your network observation interface (Layer 0).
6. Sanitise `config/` for your deployment (see README).
7. Validate the configuration: `python scripts/validate_config.py`.
8. Start the cascade: `python run.py`.

## Native dependencies (Zeek and Suricata)

Sentrix ingests Layer 0 observation logs produced by **Zeek** (protocol parser, emits `conn.log` and per-protocol logs) and **Suricata** (signature engine, emits `eve.json`). Both run on the host (or in a sidecar container) and write into the directory that Sentrix mounts as `logs/`. They are not Python packages and are installed at the OS level.

### Ubuntu 22.04 / Debian 12

```bash
# Suricata (Debian/Ubuntu main repos)
sudo apt-get update
sudo apt-get install -y suricata

# Zeek (official OpenSUSE Build Service repo)
echo deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ / | sudo tee /etc/apt/sources.list.d/security_zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update
sudo apt-get install -y zeek
```

For Ubuntu, replace `Debian_12` with `xUbuntu_22.04` in the URLs above.

### Red Hat / Rocky / CentOS

```bash
sudo dnf install -y suricata
sudo dnf copr enable @bro/zeek
sudo dnf install -y zeek
```

### Verify

```bash
zeek --version       # Zeek 6.x or newer
suricata --build-info | head -3
```

### Configure

Point Zeek and Suricata at your SPAN/mirror interface and configure them to write logs into the directory Sentrix has mounted as `logs/` (default: `./logs/`). The cascade reads `conn.log`, the protocol logs, and `eve.json` from that directory.
