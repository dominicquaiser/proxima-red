"""Gunicorn configuration for the production web container.

Logs go to stdout/stderr so the container runtime captures them
(`docker compose logs web`). Worker count is overridable via GUNICORN_WORKERS.
"""

import multiprocessing
import os

bind = "0.0.0.0:8000"

workers = int(os.environ.get("GUNICORN_WORKERS", (multiprocessing.cpu_count() * 2) + 1))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 60))

# Log to stdout/stderr.
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s %(l)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
