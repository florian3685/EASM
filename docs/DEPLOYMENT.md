# Server Deployment

This layout keeps application code under `/opt/cyberscan` and persistent data under `/var/lib/cyberscan`.

## 1. Copy The App

```bash
sudo useradd --system --home /var/lib/cyberscan --shell /usr/sbin/nologin cyberscan
sudo mkdir -p /opt/cyberscan /var/lib/cyberscan /etc/cyberscan
sudo rsync -a --exclude '.git' --exclude '.venv' --exclude 'venv' --exclude '__pycache__' ./ /opt/cyberscan/
sudo chown -R cyberscan:cyberscan /opt/cyberscan /var/lib/cyberscan
sudo chmod 750 /opt/cyberscan /var/lib/cyberscan
```

## 2. Install Python Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
sudo -u cyberscan python3 -m venv /opt/cyberscan/.venv
sudo -u cyberscan /opt/cyberscan/.venv/bin/pip install -r /opt/cyberscan/requirements.txt
```

## 3. Configure Environment

```bash
sudo cp /opt/cyberscan/deploy/env.production.example /etc/cyberscan/cyberscan.env
sudo nano /etc/cyberscan/cyberscan.env
sudo chown cyberscan:cyberscan /etc/cyberscan/cyberscan.env
sudo chmod 600 /etc/cyberscan/cyberscan.env
```

Set `EASM_WEB_SESSION_SECRET` to a long random value. Add API keys if you use those providers.

## 4. Enable The Web Service

```bash
sudo cp /opt/cyberscan/deploy/systemd/cyberscan-web.service /etc/systemd/system/cyberscan-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now cyberscan-web
sudo systemctl status cyberscan-web
```

Open the first admin setup locally or through Nginx:

```text
http://SERVER-IP/setup
```

## 5. Nginx Reverse Proxy

```bash
sudo cp /opt/cyberscan/deploy/nginx/cyberscan.conf /etc/nginx/sites-available/cyberscan.conf
sudo ln -s /etc/nginx/sites-available/cyberscan.conf /etc/nginx/sites-enabled/cyberscan.conf
sudo nginx -t
sudo systemctl reload nginx
```

Replace `cyberscan.example.com` in the Nginx file with your real domain. Put HTTPS in front of this before giving employees access, and do not expose port `18080` directly to the internet.

## Runtime Files

- `/var/lib/cyberscan/web_users.json` - employee accounts
- `/var/lib/cyberscan/results/` - generated reports
- `/var/lib/cyberscan/easm_state.db` - scan history and diff state
- `/etc/cyberscan/cyberscan.env` - API keys and server settings
