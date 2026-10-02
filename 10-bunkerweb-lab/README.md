# BunkerWeb WAF Full Stack

This guide replaces a standalone nginx web server with **BunkerWeb 1.6.13**. It installs the full stack (BunkerWeb, Scheduler, Web UI and API) together with **CrowdSec**, **Redis** and **MariaDB**, using the official install script. A demo web application then runs behind BunkerWeb: **Client → WAF / reverse proxy → web application**. The test shows BunkerWeb blocking a SQL injection and a cross-site scripting request, and CrowdSec blocking an IP.

- A **WAF** (web application firewall) checks every HTTP request and blocks attacks before they reach the application.
- A **reverse proxy** receives the client's request and forwards it to the real application in the background. The client only talks to the proxy.
- **BunkerWeb** is an open-source WAF built on NGINX. It includes **ModSecurity** (a WAF engine) with the **OWASP CRS** (Core Rule Set, a free set of attack-detection rules).

What this lab installs and sets up:

| Part | What | Where |
|---|---|---|
| [A](#part-a-retire-the-old-nginx) | Back up and remove the old standalone nginx | bunkerweb-server |
| [B](#part-b-install-the-bunkerweb-full-stack) | Install BunkerWeb 1.6.13 full stack + CrowdSec + Redis + MariaDB + API (official script) | bunkerweb-server |
| [C](#part-c-finish-the-setup-wizard-web-ui) | Finish the setup wizard: Web UI admin and HTTPS | your browser |
| [D](#part-d-turn-on-api-authentication) | Turn on API authentication | bunkerweb-server |
| [E](#part-e-put-the-web-application-behind-bunkerweb) | Put the web application behind BunkerWeb | bunkerweb-server, Web UI |

## Table of contents

1. [Architecture](#1-architecture)
2. [What you need](#2-what-you-need)
3. [Firewall](#3-firewall)
4. [Installation steps](#4-installation-steps)
5. [Test](#5-test)
6. [Common problems](#6-common-problems)
7. [Next steps](#7-next-steps)

Files in this folder:

| File | Copy to | Used in |
|---|---|---|
| [`configs/demo-app.service`](configs/demo-app.service) | bunkerweb-server: `/etc/systemd/system/demo-app.service` | [Step E1](#part-e-put-the-web-application-behind-bunkerweb) |

---

## 1. Architecture

```mermaid
flowchart LR
    C["Client<br/>(browser, curl)"] -- "HTTPS 443<br/>HTTP 80" --> BW
    LE["Let's Encrypt"] -- "certificate check<br/>HTTP 80" --> BW
    subgraph VM["bunkerweb-server (Ubuntu 22.04)"]
        BW["BunkerWeb (NGINX)<br/>ModSecurity + OWASP CRS<br/>reverse proxy"]
        BW -- "app FQDN<br/>127.0.0.1:8081" --> APP["Web application<br/>(demo app)"]
        BW -- "UI FQDN<br/>127.0.0.1:7000" --> UI["Web UI"]
        SCH["Scheduler"] -- "pushes config<br/>internal API 127.0.0.1:5000" --> BW
        SCH --> DB["MariaDB<br/>settings"]
        UI --> DB
        API["BunkerWeb API<br/>127.0.0.1:8888"] --> DB
        BW <-- "bans, metrics" --> R["Redis<br/>127.0.0.1:6379"]
        BW -- "is this IP banned?<br/>127.0.0.1:8080" --> CS["CrowdSec"]
        CS -- "reads" --> L["/var/log/bunkerweb/"]
    end
```

| Component | Job |
|---|---|
| BunkerWeb | The NGINX-based WAF and reverse proxy. Only it listens on the internet (80/443) |
| Scheduler | The "brain": reads all settings, runs jobs (certificates, blacklists), and pushes the config to BunkerWeb |
| Web UI | Web interface to manage services, settings, bans and reports. It runs behind BunkerWeb itself |
| API | REST API to manage BunkerWeb from scripts (local only, port 8888) |
| MariaDB | Database that stores all settings |
| Redis | Fast in-memory store for bans and metrics |
| CrowdSec | Reads BunkerWeb's logs, detects attacks, and shares known bad IPs. BunkerWeb asks CrowdSec about every client IP (the **bouncer**) |

---

## 2. What you need

No earlier lab is needed. This lab runs on its own VM: the one that ran the old standalone nginx.

| VM | Role | CPU / RAM / disk |
|---|---|---|
| bunkerweb-server | BunkerWeb full stack, CrowdSec, Redis, MariaDB, demo app | 2 vCPU / 8 GB / 40 GB |

Assumptions:

1. **Ubuntu 22.04**, which BunkerWeb 1.6.13 supports. Size: BunkerWeb's documentation gives 2 vCPU and 8 GB RAM as the minimum for testing. The disk size is an assumption.
2. The old nginx served a static site from `/var/www/html`. It becomes the demo app's content. If the VM never had nginx, skip Part A.
3. **BunkerWeb 1.6.13**, as in the post. Newer 1.6.x versions exist. The script locks the installed version so it does not upgrade by itself.
4. You have **two DNS names** that point to the VM's public IP: one for the Web UI and one for the app. Let's Encrypt (free HTTPS certificates) needs real names. If you have no domain, free names from **sslip.io** work: `ui.198-51-100-50.sslip.io` resolves to `198.51.100.50`.

| Placeholder | What it is | Example | Where to find it |
|---|---|---|---|
| `<VM_USER>` | The user you log in with | `ubuntu` | AWS and Oracle Cloud: `ubuntu`. Azure and Google Cloud: the name you chose |
| `<BW_PUBLIC_IP>` | Public IP of bunkerweb-server | `198.51.100.50` | Cloud console |
| `<YOUR_PUBLIC_IP>` | Public IP of your own computer | `203.0.113.25` | Search "what is my IP" |
| `<UI_FQDN>` | DNS name for the Web UI | `ui.198-51-100-50.sslip.io` | Your DNS provider (A record → `<BW_PUBLIC_IP>`), or sslip.io |
| `<APP_FQDN>` | DNS name for the web application | `app.198-51-100-50.sslip.io` | Same as above |
| `<UI_ADMIN_PASSWORD>` | Web UI admin password | you choose it | Set in [Step C1](#part-c-finish-the-setup-wizard-web-ui) |
| `<API_PASSWORD>` | BunkerWeb API password | random | Printed in [Step D1](#part-d-turn-on-api-authentication) |

**Save the UI and API passwords and the database password (printed in B3) in a password manager.** Never put them in this repository, a screenshot or a post.

---

## 3. Firewall

Only BunkerWeb is reachable from the internet. All other parts listen on `127.0.0.1` (the VM itself) and need no rules.

**Cloud firewall (security group) for bunkerweb-server:**

| Direction | Port | Source | Used for |
|---|---|---|---|
| Inbound | 22/tcp | `<YOUR_PUBLIC_IP>/32` | SSH |
| Inbound | 80/tcp | `0.0.0.0/0` | HTTP: Let's Encrypt checks and redirect to HTTPS |
| Inbound | 443/tcp | `<YOUR_PUBLIC_IP>/32` **until the setup wizard is done**, then `0.0.0.0/0` | HTTPS: the protected sites and the Web UI |
| Outbound | all | `0.0.0.0/0` (default) | Packages, rules, CrowdSec and blacklist updates, Let's Encrypt |

Until the wizard is finished, anyone who reaches `https://<BW_PUBLIC_IP>/setup` could create the admin account. That is why 443 is open only to you at first.

**ufw (on the VM):**

**Run on:** bunkerweb-server, as `<VM_USER>`

```bash
MY_IP="203.0.113.25"   # CHANGE THIS: <YOUR_PUBLIC_IP>
sudo ufw allow from "$MY_IP" to any port 22 proto tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP - BunkerWeb'
sudo ufw allow from "$MY_IP" to any port 443 proto tcp comment 'HTTPS - until wizard done'
sudo ufw --force enable
sudo ufw status numbered
```

- The SSH rule comes before `enable`, so your session stays open.
- [Step C3](#part-c-finish-the-setup-wizard-web-ui) opens 443 to everyone after the wizard.

**Check:** similar to:

```text
[ 1] 22/tcp                     ALLOW IN    203.0.113.25               # SSH
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # HTTP - BunkerWeb
[ 3] 443/tcp                    ALLOW IN    203.0.113.25               # HTTPS - until wizard done
```

(plus `(v6)` lines for port 80)

---

## 4. Installation steps

### Part A. Retire the old nginx

**Run on:** bunkerweb-server, as `<VM_USER>`

BunkerWeb installs its own NGINX version from nginx.org. Ubuntu's nginx package must be removed first. Two NGINX packages cannot be installed together, and only one program can listen on ports 80/443.

**A1. Back up the old configuration and site, then remove nginx:**

```bash
sudo systemctl stop nginx
sudo tar -czf ~/nginx-backup-$(date +%F).tar.gz /etc/nginx /var/www/html
sudo apt-get purge -y nginx nginx-common nginx-core
sudo apt-get autoremove -y
```

- `tar` saves `/etc/nginx` (old config) and `/var/www/html` (old site) into one file in your home folder.
- `apt-get purge` removes Ubuntu's nginx packages and their config. `autoremove` removes the modules they pulled in.

**Check:**

```bash
dpkg -l | grep -i nginx || echo "no nginx packages left"
sudo ss -tlnp | grep -E ':80 |:443 ' || echo "ports 80 and 443 are free"
ls -lh ~/nginx-backup-*.tar.gz
```

```text
no nginx packages left
ports 80 and 443 are free
-rw-r--r-- 1 root root 12K Oct  2 21:00 /home/ubuntu/nginx-backup-2026-10-02.tar.gz
```

### Part B. Install the BunkerWeb full stack

**Run on:** bunkerweb-server, as `<VM_USER>`

**B1. Download the official install script and check it:**

```bash
cd ~
curl -fsSL -O https://github.com/bunkerity/bunkerweb/releases/download/v1.6.13/install-bunkerweb.sh
curl -fsSL -O https://github.com/bunkerity/bunkerweb/releases/download/v1.6.13/install-bunkerweb.sh.sha256
sha256sum -c install-bunkerweb.sh.sha256
```

- The `.sha256` file holds the script's fingerprint. `sha256sum -c` checks that the downloaded script was not changed.

**Check:**

```text
install-bunkerweb.sh: OK
```

Do not run the script if the check says `FAILED`.

**B2. Run it with all components:**

```bash
BW_IP="198.51.100.50"   # CHANGE THIS: <BW_PUBLIC_IP>
chmod +x install-bunkerweb.sh
sudo ./install-bunkerweb.sh --yes --version 1.6.13 --full --api --crowdsec --redis --database mariadb --server-ip "$BW_IP"
```

| Option | Meaning |
|---|---|
| `--yes` | Use the default answer for every question (no menus) |
| `--version 1.6.13` | Install exactly this version |
| `--full` | Full stack: BunkerWeb + Scheduler + Web UI, with the setup wizard |
| `--api` | Also install and enable the BunkerWeb API service |
| `--crowdsec` | Install CrowdSec, make it read BunkerWeb's logs, and connect BunkerWeb to it |
| `--redis` | Install Redis locally and connect BunkerWeb to it |
| `--database mariadb` | Install MariaDB locally and use it instead of the default SQLite file |
| `--server-ip` | IP shown in the links at the end |

The script installs NGINX and BunkerWeb from their official repositories and locks both versions (`apt-mark hold`). It takes about 5 to 15 minutes.

**B3. Save the database password.** At the end, the script prints a block similar to this:

```text
💾 Database (auto-installed):
  Engine:   MariaDB
  Host:     127.0.0.1:3306
  Database: bw_db
  User:     bunkerweb
  Password: <generated password>
  ⚠️  This password is stored in /etc/bunkerweb/variables.env. Save it now if you need it elsewhere.
```

Save the password in your password manager. It is also stored in `/etc/bunkerweb/variables.env` (readable only with sudo). Never upload that file to GitHub.

**Check 1:** all services run:

```bash
systemctl is-active bunkerweb bunkerweb-scheduler bunkerweb-ui crowdsec mariadb redis-server
```

```text
active
active
active
active
active
active
```

**Check 2:** the integrations are wired into the main config file (secrets not shown):

```bash
sudo grep -E '^(DATABASE_URI=mariadb|USE_REDIS|REDIS_HOST|USE_CROWDSEC|CROWDSEC_API=)' /etc/bunkerweb/variables.env | sed -E 's#(://[^:]+:)[^@]+@#\1****@#'
```

Similar to:

```text
DATABASE_URI=mariadb+pymysql://bunkerweb:****@127.0.0.1:3306/bw_db
USE_REDIS=yes
REDIS_HOST=127.0.0.1
USE_CROWDSEC=yes
CROWDSEC_API=http://127.0.0.1:8080
```

- `sed` hides the database password in the output.

**Check 3:** each integration answers:

```bash
redis-cli ping
sudo mariadb -e "SHOW DATABASES;" | grep bw_db
sudo cscli bouncers list
```

Similar to:

```text
PONG
bw_db
──────────────────────────────────────────────────────────────────────────────
 Name                              IP Address  Valid  Last API pull  Type ...
──────────────────────────────────────────────────────────────────────────────
 crowdsec-bunkerweb-bouncer/v1.6   127.0.0.1   ✔️     2026-10-02...  ...
──────────────────────────────────────────────────────────────────────────────
```

- `PONG` = Redis answers. `bw_db` = BunkerWeb's database exists. The bouncer line = BunkerWeb is registered with CrowdSec (the `Last API pull` time appears after the first requests).

### Part C. Finish the setup wizard (Web UI)

**C1. Create the admin account and the UI address.**

**Run on:** your browser

1. Check that both DNS names point to the VM. On your computer: `nslookup <UI_FQDN>` and `nslookup <APP_FQDN>` both answer `<BW_PUBLIC_IP>`.
2. Open `https://<BW_PUBLIC_IP>/setup`. Accept the certificate warning (a temporary self-signed certificate).
3. Enter the **administrator username, email and password** (`<UI_ADMIN_PASSWORD>`: at least 8 characters with lowercase, uppercase, a digit and a special character). Click **Next**.
4. Enter the **server name** `<UI_FQDN>` and keep **Let's Encrypt** turned on.
5. On the overview page, click **Setup**.

**Check:** after about a minute you are sent to `https://<UI_FQDN>/` with a valid certificate (no warning). Log in with the admin account. The dashboard opens.

**C2. Confirm in the UI that the parts are connected:** open the **Instances** page. The local BunkerWeb instance shows as up. The **Plugins** page lists **CrowdSec** and **Redis** among the plugins.

**C3. Open HTTPS to everyone** (the wizard is done, the UI now needs a login):

**Run on:** bunkerweb-server, as `<VM_USER>`

```bash
sudo ufw allow 443/tcp comment 'HTTPS - BunkerWeb'
sudo ufw status numbered
```

Then delete the old "until wizard done" rule: `sudo ufw delete <number>`, using the number shown in front of it. In the cloud firewall, change the 443 rule's source to `0.0.0.0/0`.

### Part D. Turn on API authentication

**Run on:** bunkerweb-server, as `<VM_USER>`

The API only starts when it has a way to check logins. This creates an API admin user with a random password.

**D1. Create the API admin:**

```bash
API_PASS="$(openssl rand -base64 24 | tr -d '/+=')Aa1!"
echo "API password (save it now): $API_PASS"
printf 'API_USERNAME=apiadmin\nAPI_PASSWORD=%s\n' "$API_PASS" | sudo tee -a /etc/bunkerweb/api.env > /dev/null
unset API_PASS
sudo systemctl restart bunkerweb-api
```

- Line 1 makes a random password. `Aa1!` at the end makes sure it has every character type the API requires.
- Line 2 shows it once: **save it in your password manager** as `<API_PASSWORD>`.
- `tee -a` adds the two lines to the API config file `/etc/bunkerweb/api.env`. The API listens only on `127.0.0.1:8888` (this VM).

**Check 1:** the API answers:

```bash
systemctl is-active bunkerweb-api
curl -s http://127.0.0.1:8888/ping
```

```text
active
{"status":"ok","message":"pong"}
```

**Check 2:** the login works (a token comes back):

```bash
read -rsp "API password: " API_PASS; echo
curl -s -X POST -u "apiadmin:${API_PASS}" http://127.0.0.1:8888/auth | cut -c1-40
unset API_PASS
```

Similar to:

```text
{"token":"En0KEwoEYWRtaW4YAyIJCgcI
```

### Part E. Put the web application behind BunkerWeb

**E1. Start the demo application** (the old site, now on a local-only port).

**Run on:** bunkerweb-server, as `<VM_USER>`

```bash
sudo mkdir -p /opt/demo-app
sudo tar -xzf ~/nginx-backup-*.tar.gz -C /opt/demo-app --strip-components=3 var/www/html 2>/dev/null || true
[ -f /opt/demo-app/index.html ] || echo '<h1>Lab 10 demo app behind BunkerWeb</h1>' | sudo tee /opt/demo-app/index.html > /dev/null
sudo tee /etc/systemd/system/demo-app.service > /dev/null <<'EOF'
# File:    /etc/systemd/system/demo-app.service
# Machine: bunkerweb-server
# Purpose: a tiny demo web application for the lab. It serves the files in
#          /opt/demo-app on 127.0.0.1:8081 (local only). BunkerWeb is the only
#          way in from the outside. For a lab only, not for production.
[Unit]
Description=Lab 10 demo web application (behind BunkerWeb)
After=network.target

[Service]
ExecStart=/usr/bin/python3 -m http.server 8081 --bind 127.0.0.1 --directory /opt/demo-app
DynamicUser=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now demo-app
```

- Line 2 copies the old site from the Part A backup into `/opt/demo-app`. Line 3 creates a simple page if there was no old site.
- The service runs Python's built-in web server on `127.0.0.1:8081`. Only BunkerWeb on the same VM can reach it.

**Check:**

```bash
curl -s http://127.0.0.1:8081/ | head -n 3
```

The page's first lines (your old site, or `<h1>Lab 10 demo app behind BunkerWeb</h1>`).

**E2. Create the BunkerWeb service for the app.**

**Run on:** the Web UI (`https://<UI_FQDN>/`)

1. Go to **Services** → **➕ Create new service** → **Easy** mode.
2. Choose the **low** template (the basic security level: ModSecurity with OWASP CRS, bad-behavior bans, Let's Encrypt, reverse proxy).
3. Step **Web service - Front service**: **Server name** (`SERVER_NAME`) = `<APP_FQDN>`. Keep **Auto Let's Encrypt** (`AUTO_LETS_ENCRYPT`) on.
4. Step **Web service - Upstream server**: **Use reverse proxy** (`USE_REVERSE_PROXY`) = yes, **Reverse proxy host** (`REVERSE_PROXY_HOST`) = `http://127.0.0.1:8081`, **Reverse proxy URL** (`REVERSE_PROXY_URL`) = `/`.
5. Keep the other steps as they are and click **💾 Save**.

The new service appears in the **Services** list. The Scheduler gets a Let's Encrypt certificate and reloads BunkerWeb (about a minute).

**Check:** open `https://<APP_FQDN>/` in your browser. Your site loads with a valid certificate. The client now talks only to BunkerWeb, and BunkerWeb fetches the page from the app.

---

## 5. Test

Run the tests from **your computer's browser**. Do each test **once or twice only**: BunkerWeb's "bad behavior" feature bans an IP that causes many blocked requests (see [Common problems](#6-common-problems)).

**5.1 WAF (ModSecurity + OWASP CRS): an attack is blocked.**

| Open this URL | Attack type | Expected |
|---|---|---|
| `https://<APP_FQDN>/` | Normal request | Your site (status 200) |
| `https://<APP_FQDN>/?id=1' OR '1'='1` | SQL injection (tries to change a database query) | BunkerWeb's **403 Forbidden** page |
| `https://<APP_FQDN>/?q=<script>alert(1)</script>` | Cross-site scripting, XSS (tries to run JavaScript in another user's browser) | BunkerWeb's **403 Forbidden** page |

The same test with curl (Linux, macOS, or `curl.exe` in Windows PowerShell):

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<APP_FQDN>/"
curl -s -o /dev/null -w "%{http_code}\n" "https://<APP_FQDN>/?id=1%27%20OR%20%271%27=%271"
```

```text
200
403
```

(On Windows, write `-o NUL` instead of `-o /dev/null`.)

**See it in the Web UI:** go to **Reports**. The blocked requests are listed with your IP, the URL, and the reason **modsecurity**.

**5.2 CrowdSec: a banned IP is blocked.**

**Run on:** bunkerweb-server, as `<VM_USER>`

```bash
MY_IP="203.0.113.25"   # CHANGE THIS: <YOUR_PUBLIC_IP>
sudo cscli decisions add --ip "$MY_IP" --duration 2m --reason "lab 10 test"
```

- This tells CrowdSec to ban your IP for 2 minutes. SSH is not affected. Only web traffic through BunkerWeb is checked.

Now reload `https://<APP_FQDN>/` in your browser: BunkerWeb shows a **403** page. Remove the ban (or wait 2 minutes):

```bash
sudo cscli decisions delete --ip "$MY_IP"
```

**Check:** `sudo cscli decisions list` shows no decision for your IP, and the site loads again.

**5.3 Redis, MariaDB and API:** these were tested in Checks B3 and D. After the tests above, Redis also holds BunkerWeb's data: `redis-cli dbsize` shows a number larger than `0`.

**The setup works when** the normal request returns 200, both attacks return 403 and appear in **Reports**, and the CrowdSec ban blocks the site until it is removed.

---

## 6. Common problems

| Problem | Fix |
|---|---|
| The script stops because nginx is already installed or ports 80/443 are in use | Part A was skipped or incomplete. Run the Part A check: no nginx packages, ports 80/443 free |
| The wizard or the app shows a certificate warning after setup | Let's Encrypt failed. Check: the DNS name points to `<BW_PUBLIC_IP>` (`nslookup`), and port 80 is open to `0.0.0.0/0` (cloud + ufw). With sslip.io, Let's Encrypt limits can be reached: try again later or use your own domain. Logs: `sudo tail -n 50 /var/log/bunkerweb/scheduler.log` |
| Your browser suddenly gets 403 on every page | You were banned by "bad behavior" (too many blocked requests) or by CrowdSec. Check `sudo bwcli bans` and `sudo cscli decisions list`. Unban: `sudo bwcli unban <YOUR_PUBLIC_IP>` or `sudo cscli decisions delete --ip <YOUR_PUBLIC_IP>` |
| `bunkerweb-api` is not `active` | No login method is set. Check that `/etc/bunkerweb/api.env` has `API_USERNAME` and `API_PASSWORD` (Part D), then `sudo systemctl restart bunkerweb-api`. Errors: `sudo journalctl -u bunkerweb-api -n 30` |
| `https://<APP_FQDN>/` shows a 502 error | BunkerWeb cannot reach the app. `systemctl is-active demo-app` must print `active`, and `curl http://127.0.0.1:8081/` must work (E1) |

---

## 7. Next steps

- **OWASP attack categories, ModSecurity and the CRS** (paranoia level, exclusions for false positives): [ModSecurity](https://docs.bunkerweb.io/latest/features/#modsecurity)
- **Rate limiting** (requests per second per IP): [Limit](https://docs.bunkerweb.io/latest/features/#limit)
- **Bot protection** (JavaScript, captcha challenges): [Antibot](https://docs.bunkerweb.io/latest/features/#antibot)
- **GeoIP restrictions** (allow or block countries): [Country](https://docs.bunkerweb.io/latest/features/#country)
- **Stronger presets**: the **medium** and **high** templates add antibot, rate limiting and more. [Web UI](https://docs.bunkerweb.io/latest/web-ui/)
- **CrowdSec AppSec** (CrowdSec's own WAF component) and the CrowdSec console: [CrowdSec](https://docs.bunkerweb.io/latest/features/#crowdsec)
- **Reverse proxy options** (paths, websockets, several back ends): [Reverse proxy](https://docs.bunkerweb.io/latest/features/#reverse-proxy)
