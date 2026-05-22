<div align="center">
   <img src=".github/assets/logo.png" alt="Logo" width="300">
   <br><a href="https://github.com/apurvsinghgautam/robin/actions/workflows/binary.yml"><img alt="Build" src="https://github.com/apurvsinghgautam/robin/actions/workflows/binary.yml/badge.svg"></a> <a href="https://github.com/apurvsinghgautam/robin/releases"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/apurvsinghgautam/robin"></a> <a href="https://hub.docker.com/r/apurvsg/robin"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/apurvsg/robin"></a>
   <h1>Robin: AI-Powered Dark Web OSINT Tool</h1>

   <p>Robin is an AI-powered tool for conducting dark web OSINT investigations. It leverages LLMs to refine queries, filter search results from dark web search engines, and provide an investigation summary.</p>
   <a href="#installation">Installation</a> &bull; <a href="#usage">Usage</a> &bull; <a href="#contributing">Contributing</a> &bull; <a href="#acknowledgements">Acknowledgements</a><br><br>
</div>

![Demo](.github/assets/screen.png)
![Demo](.github/assets/screen-ui.png)
![Workflow](.github/assets/robin-workflow.png)

---

## Features

- ⚙️ **Modular Architecture** – Clean separation between search, scrape, OSINT, enrichment and LLM workflows.
- 🤖 **Multi-Model Support** – OpenAI (GPT-4.1/5/5-mini), Claude (Sonnet 4-5), Gemini 2.5, OpenRouter, Ollama.
- 🌑 **Dark web + Clearweb OSINT** – Onion search engines (Ahmia, Tor66, Torch v3, Haystack, ...) **plus** real OSINT APIs:
   - `ransomware.live` — live ransomware victim feed + group profiles
   - `crt.sh` — Certificate Transparency, real subdomain enumeration
   - `haveibeenpwned.com` — public breach catalog
   - `cavalier.hudsonrock.com` — infostealer infection lookup (free OSINT endpoints)
   - GitHub code search — find leaked credentials in public repos (token-optional)
   - DuckDuckGo dorks against Pastebin, Telegram, BreachForums mirrors
- 🔬 **IOC enrichment** – Each extracted IOC is enriched with real data:
   - Domains → DNS A records, RDAP WHOIS, crt.sh subdomains
   - IPs → reverse DNS, geo/ASN (ipapi.co), AbuseIPDB (optional)
   - Hashes → CIRCL hashlookup + Malware Bazaar verdict
   - CVEs → NVD short description + CVSS score
   - Emails → HudsonRock stealer logs
- 🩺 **Health check** – `robin doctor` (or sidebar button) pings every source so you know what's up before you search.
- 🐳 **Docker-Ready** – Optional Docker deployment for clean, isolated usage.
- 📝 **Markdown + PDF Reports** – Save sources, IOCs, enrichment and LLM summary in both formats.
- 🧩 **Extensible** – Adding a new OSINT source is a single function in [osint_sources.py](osint_sources.py).

---

## ⚠️ Disclaimer
> This tool is intended for educational and lawful investigative purposes only. Accessing or interacting with certain dark web content may be illegal depending on your jurisdiction. The author is not responsible for any misuse of this tool or the data gathered using it.
>
> Use responsibly and at your own risk. Ensure you comply with all relevant laws and institutional policies before conducting OSINT investigations.
>
> Additionally, Robin leverages third-party APIs (including LLMs). Be cautious when sending potentially sensitive queries, and review the terms of service for any API or model provider you use.

## Installation
> [!NOTE]
> The tool needs Tor to do the searches. You can install Tor using `apt install tor` on Linux/Windows(WSL) or `brew install tor` on Mac. Once installed, confirm if Tor is running in the background.

> [!TIP]
> You can provide OpenAI or Anthropic or Google API key by either creating .env file (refer to sample env file in the repo) or by setting env variables in PATH.
>
> For Ollama, provide `http://host.docker.internal:11434` as `OLLAMA_BASE_URL` in your env if running using docker method or `http://127.0.0.1:11434` for other methods. You might need to serve Ollama on 0.0.0.0 depending on your OS. You can do that using `OLLAMA_HOST=0.0.0.0 ollama serve &`.

### Docker (Web UI Mode) [Recommended]

- Pull the latest Robin docker image
```bash
docker pull apurvsg/robin:latest
```

- Run the docker image as:
```bash
docker run --rm \
   -v "$(pwd)/.env:/app/.env" \
   --add-host=host.docker.internal:host-gateway \
   -p 8501:8501 \
   apurvsg/robin:latest ui --ui-port 8501 --ui-host 0.0.0.0
```

### Release Binary (CLI Mode)

- Download the appropriate binary for your system from the [latest release](https://github.com/apurvsinghgautam/robin/releases/latest)
- Unzip the file, make it executable 
```bash
chmod +x robin
```

- Run the binary as:
```bash
robin cli --model gpt-4.1 --query "ransomware payments"
```

### Using Python (Development Version)

- With `Python 3.10+` installed, run the following:

```bash
pip install -r requirements.txt
python main.py -m gpt-4.1 -q "ransomware payments" -t 12
```

---

## Usage

### CLI

```bash
# Default pipeline (dark web + clearweb OSINT + IOC enrichment)
robin cli -m gpt-5-mini -q "acme corp leak"

# Restrict to specific clearweb OSINT sources
robin cli -q "lockbit" --clearweb-sources ransomware.live,hibp,ddg:telegram

# Investigation on a domain (will auto-pivot to crt.sh / HudsonRock / WHOIS)
robin cli -q "acme.com" --pdf-report --download-files

# Disable enrichment if you just want raw findings
robin cli -q "stealer logs france" --no-enrich

# Health check every onion engine + OSINT API
robin doctor

# Web UI
robin ui --ui-port 8501
```

#### CLI options

| Flag | Description |
| --- | --- |
| `-m / --model` | LLM model (Claude / GPT / Gemini / OpenRouter / Ollama) |
| `-q / --query` | Search target (company, domain, email, hash, CVE…) |
| `-t / --threads` | Concurrent workers (default 8) |
| `-o / --output` | Output base filename (default: timestamped) |
| `--enrich / --no-enrich` | IOC enrichment (DNS, WHOIS, hash lookup, geo). Default on. |
| `--no-clearweb-osint` | Skip clearweb OSINT APIs (faster but less data). |
| `--clearweb-sources` | Comma list. Available: `ransomware.live`, `crt.sh`, `hibp`, `github`, `ddg:pastebin`, `ddg:ghostbin`, `ddg:telegram`, `ddg:breachforum` |
| `--download-files` | Download text-like files (txt/csv/json/sql/pdf) found in results |
| `--pdf-report` | Generate a PDF report alongside the markdown summary |
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request if you have major feature updates.

- Fork the repository
- Create your feature branch (git checkout -b feature/amazing-feature)
- Commit your changes (git commit -m 'Add some amazing feature')
- Push to the branch (git push origin feature/amazing-feature)
- Open a Pull Request

Open an Issue for any of these situations:
- If you spot a bug or bad code
- If you have a feature request idea
- If you have questions or doubts about usage
- If you have minor code changes

---

## Acknowledgements

- Idea inspiration from [Thomas Roccia](https://x.com/fr0gger_) and his demo of [Perplexity of the Dark Web](https://x.com/fr0gger_/status/1908051083068645558).
- Tools inspiration from my [OSINT Tools for the Dark Web](https://github.com/apurvsinghgautam/dark-web-osint-tools) repository.
- LLM Prompt inspiration from [OSINT-Assistant](https://github.com/AXRoux/OSINT-Assistant) repository.
- Logo Design by my friend [Tanishq Rupaal](https://github.com/Tanq16/)
- Workflow Design by [Chintan Gurjar](https://www.linkedin.com/in/chintangurjar)





