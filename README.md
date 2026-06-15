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

## Portal Routes

- `/dashboard` - overview, latest scan, latest PDFs and recent report files
- `/scans` - start authorized customer-domain scans and watch jobs
- `/reports` - browse generated JSON, HTML and PDF reports
- `/admin` - manage employee users and roles

## Security Notes

- Only scan customer domains with written authorization or an agreed contract scope.
- `web_users.json`, `.env`, generated reports, local databases and virtual environments are ignored by Git.
- Active exploitation modules should only be enabled for explicitly approved test scopes.
