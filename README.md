# link-ed.it CyberScan

Internal web portal for authorized customer-domain security scans.

## Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 web_app.py --host 127.0.0.1 --port 18080
```

Open `http://127.0.0.1:18080/setup` first and create the initial admin user.

## Server Deployment

Use `docs/DEPLOYMENT.md` plus the files in `deploy/` for a server install with:

- app code in `/opt/cyberscan`
- employee accounts, reports and scan state in `/var/lib/cyberscan`
- secrets and API keys in `/etc/cyberscan/cyberscan.env`

## Portal Routes

- `/dashboard` - overview, latest scan, latest PDFs and recent report files
- `/scans` - start authorized customer-domain scans and watch jobs
- `/reports` - browse generated JSON, HTML and PDF reports
- `/admin/users` - manage employee users and roles
- `/admin/api-keys` - manage scan-provider API keys without exposing values in the UI

## Security Notes

- Only scan customer domains with written authorization or an agreed contract scope.
- `web_users.json`, `.env`, generated reports, local databases and virtual environments are ignored by Git.
- Active exploitation modules should only be enabled for explicitly approved test scopes.
