# ============================================================
# VULNERABLE IMAGE - intentionally uses old base + packages
# for DevSecOps scanning demo purposes (SAST / SCA / Trivy)
# ============================================================
FROM python:3.9-bullseye

# set work directory
WORKDIR /app

# Intentional misconfiguration: hardcoded non-secret env vars (demo)
ENV FOO=bar
ENV BAZ=qux

RUN apt-get update && apt-get install --no-install-recommends -y \
    dnsutils \
    libpq-dev \
    python3-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Intentional: pinned old pip version (demonstrates outdated tooling)
RUN python -m pip install --no-cache-dir pip==22.0.4

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# copy project
COPY . /app/

EXPOSE 8000

RUN python3 /app/manage.py migrate
WORKDIR /app/pygoat/
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "6", "pygoat.wsgi"]
