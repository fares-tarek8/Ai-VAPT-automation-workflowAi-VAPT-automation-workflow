# AI-Assisted VAPT Automation Workflow

An experimental AI-assisted Vulnerability Assessment and Penetration Testing (VAPT) project using FastAPI and NVIDIA NIM.

## Current Features

- FastAPI backend with a `/analyze` endpoint.
- NVIDIA NIM integration for analyzing supplied security scan output.
- Structured report validation using Pydantic.
- Team API key authentication.
- Target allowlist validation.
- CTF and assessment modes with restricted action names.
- Human review required for generated findings.

**Important:** This version analyzes supplied scan output. It does not yet automatically execute discovery tools or perform vulnerability exploitation.

## Requirements

- Python 3.11 or a compatible Python version.
- Git.
- An NVIDIA NIM API key.
- A team API key chosen by the project operator.

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/fares-tarek8/Ai-VAPT-automation-workflow.git
cd Ai-VAPT-automation-workflow
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Set your own NVIDIA NIM API key and team API key. Do not commit credentials to Git.

```bash
export NVIDIA_API_KEY="YOUR_NVIDIA_API_KEY"
export TEAM_API_KEY="YOUR_TEAM_API_KEY"
export TARGET_ALLOWLIST="192.0.2.0/24"
```

The allowlist above is for documentation-only testing. Replace it with a narrowly scoped network you own or are explicitly authorized to assess before testing real devices.

Each team member should use their own NVIDIA credentials where possible. The team API key should be shared only with trusted collaborators.

### 5. Start the API

```bash
uvicorn vapt_api:app --host 127.0.0.1 --port 8000
```

Open the interactive API documentation at:

http://127.0.0.1:8000/docs

The server listens on localhost by default. It is not remotely accessible with this configuration.

## Safety Notes

- Only assess systems you own or have explicit permission to test.
- The target allowlist is a technical restriction, not proof of authorization.
- The current scope manager validates IP addresses and action names; it does not execute security tools.
- Treat AI-generated findings as unverified until independently confirmed.
- Never commit API keys, passwords, `.env` files, or virtual environments.

## Project Status

Early development. Automated tool execution, verification workflows, and deployment hardening remain future work.
