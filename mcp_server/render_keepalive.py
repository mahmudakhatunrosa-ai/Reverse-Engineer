"""
Render 24/7 Free-Tier Keep-Alive Ping Utility
============================================
Render free instances go to sleep after 15 minutes of inactivity.
Run this lightweight keepalive script locally, via GitHub Actions cron,
or using a free uptime monitor (UptimeRobot, Cron-Job.org, BetterUptime)
to ping your Render URL every 10 minutes and keep it 100% warm 24/7.
"""

import time
import sys
import httpx
from datetime import datetime

def run_keepalive(render_url: str, interval_seconds: int = 600):
    endpoint = f"{render_url.rstrip('/')}/health"
    print(f"[{datetime.now().isoformat()}] Starting Keep-Alive for {endpoint} (Interval: {interval_seconds}s)")

    while True:
        try:
            resp = httpx.get(endpoint, timeout=15.0)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] PING {endpoint} -> HTTP {resp.status_code}")
        except Exception as err:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] PING ERROR: {err}")
        time.sleep(interval_seconds)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python render_keepalive.py https://your-app-name.onrender.com")
        sys.exit(1)
    run_keepalive(sys.argv[1])
