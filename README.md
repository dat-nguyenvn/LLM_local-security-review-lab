# Security Agent Playground

A small security training lab for practicing source-code reviews. It contains
two intentionally vulnerable apps, a rule-based scanner, and an LLM agent that
uses a local Ollama model.

> **Warning:** This repository intentionally contains insecure training code.
> Run it only on your own computer. Do not deploy it publicly, use it with real
> data, or reuse its vulnerable patterns in production. The Python app and the
> web server examples below bind to `127.0.0.1`.

## Repository structure

```text
.
├── app1/                   # HTML/CSS/JavaScript web app
├── app2/                   # Python HTTP app
├── security_agent.py       # Rule-based source scanner
├── llm_security_agent.py   # Source review using local Ollama
└── README.md
```

## Requirements

- Python 3.10 or later.
- Ollama and the `qwen2.5-coder:3b` model to use the LLM agent.
- No third-party Python packages are required.

## Installation

### 1. Get the source code

If you have already cloned the repository:

```bash
cd security-agent-playground
```

Or clone it from GitHub:

```bash
git clone <your-repository-url>
cd <repository-name>
```

### 2. Install and prepare Ollama

Install Ollama by following the instructions for your operating system at
[ollama.com/download](https://ollama.com/download).

Download the model once:

```bash
ollama pull qwen2.5-coder:3b
```

Ollama manages the model in its local model store. The exact location depends
on your operating system and the account running Ollama.

## Run the applications

Run each command below in a separate terminal from the repository root.

### App 1: Web app

```bash
python3 -m http.server 8001 --bind 127.0.0.1 --directory app1
```

Open <http://127.0.0.1:8001> in your browser. Stop the server with `Ctrl+C`.

### App 2: Python app

```bash
python3 app2/app.py
```

Open <http://127.0.0.1:8002> in your browser. Stop the server with `Ctrl+C`.

## Run the security agents

### Rule-based scanner

```bash
python3 security_agent.py
```

The scanner looks for a small set of known source-code patterns. It does not
use an LLM, run the apps, or scan the network.

### Local LLM agent

Make sure Ollama is running. If it does not start automatically, open a separate
terminal and run:

```bash
ollama serve
```

Then, from the repository root, run:

```bash
python3 llm_security_agent.py
```

The agent sends the source code of `app1/index.html`, `app1/app.js`, and
`app2/app.py` to Ollama on `localhost`. It only reads source code; it does not
run the apps or scan the network. To select a different model already installed
in Ollama:

```bash
python3 llm_security_agent.py --model <model-name>
```

The agent only allows an Ollama server on localhost to help prevent source code
from being sent to an external service. LLM reports can miss issues or include
false positives, so verify all findings manually.

## Intentional training vulnerabilities

- **App 1:** inserts user input into `innerHTML`; checks a demo access code and
  displays the protected content in browser-side JavaScript.
- **App 2:** concatenates a search term into SQL; joins a user-supplied filename
  to a path without restricting it to the `public/` directory.

Use these examples only to learn how to identify and fix vulnerabilities. Do
not test against systems or data you do not own or have permission to assess.
