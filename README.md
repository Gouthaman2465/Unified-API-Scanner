```
 █████╗ ███████╗ ██████╗ ██╗███████╗      █████╗ ██████╗ ██╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝     ██╔══██╗██╔══██╗██║
███████║█████╗  ██║  ███╗██║███████╗     ███████║██████╔╝██║
██╔══██║██╔══╝  ██║   ██║██║╚════██║     ██╔══██║██╔═══╝ ██║
██║  ██║███████╗╚██████╔╝██║███████║     ██║  ██║██║     ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝     ╚═╝  ╚═╝╚═╝     ╚═╝
```

# Aegis-API — Unified API Security Scanner

![Python](https://img.shields.io/badge/python-3.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-API1%20%7C%20API2%20%7C%20API3%20%7C%20API4-red)
![Protocols](https://img.shields.io/badge/protocols-REST%20%7C%20SOAP%20%7C%20GraphQL-purple)
![Status](https://img.shields.io/badge/status-active-brightgreen)

**Unified API security scanner for REST, SOAP, and GraphQL APIs.**

Aegis-API is an open-source API security assessment framework that detects OWASP API Top 10 vulnerabilities across all three major API protocols under a single tool. Built as a student capstone security project — covering REST, SOAP, and GraphQL in one unified scanner.

---

## Protocol Support Matrix

| Vulnerability / Test                    | REST | SOAP | GraphQL |
|---------------------------------------- |:----:|:----:|:-------:|
| IDOR / BOLA (API1)                      |  ✅  |  ✅  |   ✅    |
| Broken Authentication — JWT (API2)      |  ✅  |  —   |   ✅    |
| Broken Authentication — WS-Security     |  —   |  ✅  |   —     |
| Mass Assignment / Data Exposure (API3)  |  ✅  |  ✅  |   ✅    |
| Rate Limit / Resource Consumption (API4)|  ✅  |  —   |   ✅    |
| XXE Injection                           |  —   |  ✅  |   —     |
| XML / SOAP Injection                    |  —   |  ✅  |   —     |
| WSDL Enumeration (Info Disclosure)      |  —   |  ✅  |   —     |
| GraphQL Introspection Abuse             |  —   |  —   |   ✅    |
| GraphQL Query Depth Attack              |  —   |  —   |   ✅    |
| GraphQL Field Authorization Bypass      |  —   |  —   |   ✅    |
| GraphQL Batching / Alias Abuse          |  —   |  —   |   ✅    |
| Swagger / OpenAPI Discovery             |  ✅  |  —   |   —     |
| GraphQL Schema Discovery                |  —   |  —   |   ✅    |
| Async Concurrent Scanning               |  ✅  |  ✅  |   ✅    |
| CVSS Scoring (dynamic)                  |  ✅  |  ✅  |   ✅    |
| OWASP Mapping in Reports                |  ✅  |  ✅  |   ✅    |

> ✅ = Supported | — = Not applicable to this protocol

---

## OWASP API Top 10 Coverage

| OWASP ID | Vulnerability Name                  | REST | SOAP | GraphQL |
|----------|-------------------------------------|:----:|:----:|:-------:|
| API1     | Broken Object Level Authorization   |  ✅  |  ✅  |   ✅    |
| API2     | Broken Authentication               |  ✅  |  ✅  |   ✅    |
| API3     | Broken Object Property Level Auth   |  ✅  |  ✅  |   ✅    |
| API4     | Unrestricted Resource Consumption   |  ✅  |  —   |   ✅    |
| API5     | Broken Function Level Authorization | 🔜  |  —   |  🔜    |
| API6     | Unrestricted Access to Business Flows| 🔜 |  —   |  🔜    |
| API7     | Server-Side Request Forgery         | 🔜  |  🔜  |  🔜    |
| API8     | Security Misconfiguration           |  ✅  |  ✅  |   ✅    |
| API9     | Improper Inventory Management       |  ✅  |  ✅  |   ✅    |
| API10    | Unsafe Consumption of APIs          | 🔜  |  🔜  |  🔜    |

> ✅ = Implemented | 🔜 = Planned | — = Not applicable

---

## Installation

### Requirements

- Python 3.9 or higher
- pip
- Docker (for lab environments only)

### Step 1 — Clone the repository

```bash
git clone https://github.com/yourusername/aegis-api.git
cd aegis-api
```

### Step 2 — Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Verify installation

```bash
python main.py --help
```

You should see the Aegis-API CLI help output listing all available flags.

---

## Usage

### Auto-detect protocol (recommended)

```bash
python main.py --url http://target/api --protocol auto
```

Aegis-API will probe the target and automatically detect whether it is a REST, SOAP, or GraphQL API, then route to the correct scanner chain.

### REST API scan

```bash
python main.py --url http://localhost:8888/api --protocol rest --token YOUR_JWT_TOKEN
```

### SOAP API scan

```bash
python main.py --url http://localhost:8080/ws --protocol soap
```

### GraphQL API scan

```bash
python main.py --url http://localhost:5013/graphql --protocol graphql
```

### With Burp Suite proxy

```bash
python main.py --url http://target/api --protocol rest --proxy http://127.0.0.1:8080
```

### With custom wordlist (for IDOR fuzzing)

```bash
python main.py --url http://target/api --protocol rest -p wordlists/ids.txt
```

### Full flag reference

| Flag           | Description                                      | Default          |
|----------------|--------------------------------------------------|------------------|
| `--url`        | Target API base URL (required)                   | —                |
| `--protocol`   | Protocol: rest / soap / graphql / auto           | auto             |
| `--token`      | JWT Bearer token for authenticated scans         | —                |
| `--proxy`      | Proxy URL (e.g. Burp Suite: http://127.0.0.1:8080) | —             |
| `-p`           | Path to ID wordlist file for IDOR fuzzing        | built-in list    |
| `--output`     | Output directory for reports                     | reports/         |
| `--log`        | Path for CSV audit log                           | audit_log.csv    |
| `--timeout`    | Request timeout in seconds                       | 10               |
| `--retries`    | Max retries per request                          | 3                |
| `--concurrency`| Number of concurrent async workers               | 10               |

---

## Sample Output

Pre-generated sample outputs from all three lab environments are in the [`sample_outputs/`](./sample_outputs/) folder:

| File | Contents |
|------|----------|
| [`sample_VAPT_Report.pdf`](./sample_outputs/sample_VAPT_Report.pdf) | Full PDF report with REST + SOAP + GraphQL findings, OWASP mapping, CVSS scores, remediation |
| [`sample_audit_log.csv`](./sample_outputs/sample_audit_log.csv) | Multi-protocol CSV scan log with timestamps |
| [`sample_payloads.txt`](./sample_outputs/sample_payloads.txt) | Raw request/response evidence from all three protocols |

See [`sample_outputs/README.md`](./sample_outputs/README.md) for a full breakdown of each file.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                        │
│              argparse → flags → dispatcher                  │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              discovery/protocol_detector.py                 │
│   Probe target → detect REST / SOAP / GraphQL / UNKNOWN     │
└────────────┬──────────────────┬────────────────┬────────────┘
             │                  │                │
             ▼                  ▼                ▼
┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│  REST Scanner  │  │  SOAP Scanner   │  │ GraphQL Scanner  │
│  Chain         │  │  Chain          │  │ Chain            │
│                │  │                 │  │                  │
│ swagger_parser │  │ wsdl_parser     │  │ graphql_schema   │
│ idor.py        │  │ wsdl_enum.py    │  │ introspection.py │
│ mass_assign.py │  │ xxe.py          │  │ depth_limit.py   │
│ rate_limit.py  │  │ xml_injection.py│  │ field_auth.py    │
│ jwt.py (shared)│  │ ws_security.py  │  │ batch_abuse.py   │
└────────┬───────┘  └────────┬────────┘  └───────┬──────────┘
         │                   │                    │
         └───────────────────┴────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    utils/ (shared layer)                    │
│  http_client.py — proxy, retries, headers                   │
│  logger.py      — CSV audit log                             │
│  helpers.py     — CVSS scoring, OWASP mapping               │
│  reporting.py   — unified PDF report generator              │
└─────────────────────────────────────────────────────────────┘
```

**Request flow:**
1. `main.py` parses CLI flags and calls `protocol_detector.py`
2. Detector probes target and returns protocol label
3. Correct scanner chain is activated
4. All scanners share `utils/http_client.py` for HTTP traffic
5. Findings are collected, CVSS scored, and OWASP mapped via `utils/helpers.py`
6. `utils/reporting.py` generates the final PDF report
7. `utils/logger.py` writes the CSV audit log throughout

---

## Folder Structure

```
aegis_api/
│
├── scanners/
│   ├── rest/           ← REST-specific vulnerability scanners
│   │   ├── idor.py
│   │   ├── mass_assignment.py
│   │   └── rate_limit.py
│   ├── soap/           ← SOAP-specific vulnerability scanners
│   │   ├── wsdl_enum.py
│   │   ├── xxe.py
│   │   ├── xml_injection.py
│   │   └── ws_security.py
│   ├── graphql/        ← GraphQL-specific vulnerability scanners
│   │   ├── introspection.py
│   │   ├── depth_limit.py
│   │   ├── field_auth.py
│   │   └── batch_abuse.py
│   └── jwt.py          ← Shared JWT analyzer (REST + GraphQL)
│
├── discovery/          ← Protocol detection and endpoint discovery
│   ├── protocol_detector.py
│   ├── swagger_parser.py
│   ├── wsdl_parser.py
│   └── graphql_schema.py
│
├── utils/              ← Shared utilities used by all protocols
│   ├── logger.py
│   ├── reporting.py
│   ├── helpers.py
│   └── http_client.py
│
├── payloads/           ← Attack payload files per protocol
│   ├── soap/
│   │   ├── xxe_payloads.xml
│   │   └── sqli_soap.xml
│   └── graphql/
│       ├── depth_bomb.graphql
│       └── batch_payloads.graphql
│
├── sample_outputs/     ← Pre-generated scan outputs for review
│   ├── sample_VAPT_Report.pdf
│   ├── sample_audit_log.csv
│   ├── sample_payloads.txt
│   └── README.md
│
├── tests/              ← Unit and integration tests
│   ├── rest/
│   ├── soap/
│   └── graphql/
│
├── .github/workflows/  ← CI/CD pipeline
│   └── aegis_scan.yml
│
├── main.py             ← Entry point and protocol router
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Lab Environments

Aegis-API is tested against purpose-built vulnerable API labs. **Never run this tool against systems you do not own or have explicit written permission to test.**

### REST — crAPI (Completely Ridiculous API)

Official OWASP vulnerable REST API lab. Tests IDOR, Mass Assignment, JWT, Rate Limit.

```bash
docker pull crapi/crapi
docker-compose -f crapi-docker-compose.yml up -d
```

Default URL after startup: `http://localhost:8888`

Verify: visit `http://localhost:8888` in your browser — you should see the crAPI web interface.

### SOAP — WebGoat

OWASP WebGoat is a deliberately vulnerable application with SOAP-based lessons covering XXE, XML injection, and WS-Security weaknesses.

```bash
docker pull webgoat/goat-and-wolf
docker run -p 8080:8080 -p 9090:9090 -e WEBGOAT_HOST=0.0.0.0 webgoat/goat-and-wolf
```

Default URL: `http://localhost:8080/WebGoat`

WSDL endpoint for testing: `http://localhost:8080/WebGoat/services/HelloWS?wsdl`

### GraphQL — DVGA (Damn Vulnerable GraphQL Application)

Purpose-built vulnerable GraphQL app. Tests introspection abuse, depth attacks, batching abuse, field-level authorization bypass.

```bash
docker pull dolevf/dvga
docker run -t -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga
```

Default URL: `http://localhost:5013/graphql`

Verify introspection is enabled: send `{"query": "{ __schema { types { name } } }"}` — you should receive a full schema dump.

### Which phase tests against which lab

| Phase | Lab Used  | Protocol | What Is Tested                          |
|-------|-----------|----------|-----------------------------------------|
| 1–3   | crAPI     | REST     | IDOR, Mass Assignment, Swagger discovery|
| 4     | WebGoat   | SOAP     | WSDL enumeration                        |
| 5     | DVGA      | GraphQL  | Introspection schema discovery          |
| 6     | crAPI     | REST     | JWT analysis                            |
| 7     | WebGoat   | SOAP     | XXE injection                           |
| 8     | WebGoat   | SOAP     | XML injection, WS-Security              |
| 9     | DVGA      | GraphQL  | Depth limit attack                      |
| 10    | DVGA      | GraphQL  | Field authorization bypass              |
| 11    | DVGA      | GraphQL  | Batching / alias abuse                  |
| 12    | crAPI     | REST     | Rate limit testing                      |
| 13    | All three | ALL      | Unified PDF report generation           |

---

## Contributing

Contributions are welcome. To add a new scanner module:

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-module-name`
3. Follow the existing module structure — one file per vulnerability class, one function per test
4. Add a corresponding test in the `tests/` folder
5. Update the Protocol Support Matrix in this README
6. Submit a pull request with a clear description of what vulnerability you are testing and against which protocol

Please read the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/) before contributing new test modules to ensure correct OWASP mapping.

---

## Legal Disclaimer

**This tool is intended for authorized security testing only.**

Aegis-API must only be run against:
- Systems you own
- Systems where you have explicit written permission from the owner to perform security testing

Running this tool against systems without authorization may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), or equivalent laws in your jurisdiction.

The author and contributors accept no liability for misuse of this tool. Use responsibly and legally.

---

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for full terms.

---

## Author

Built by a final year Computer Science student as a capstone project in API security.
Covers OWASP API Top 10 across REST, SOAP, and GraphQL in a unified open-source scanner.
