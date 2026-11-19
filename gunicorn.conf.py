import os

bind = os.environ.get("SR_BIND", "unix:/run/api/api.sock")
workers = 1
worker_class = "uvicorn.workers.UvicornWorker"
# Requests are short: extractions run in the worker process.
timeout = int(os.environ.get("SR_GUNICORN_TIMEOUT", "30"))
graceful_timeout = int(os.environ.get("SR_GUNICORN_GRACEFUL_TIMEOUT", "30"))
# gunicorn's own logger, fixed when the master starts (a reload does not change it): an uploaded log_level
# changes the app's logs in both processes, not these lines.
loglevel = os.environ.get("SR_LOG_LEVEL", "info").lower()
accesslog = None
umask = 0o007  # socket /run/api/api.sock 0770 sr:sr; Caddy reads it as root
