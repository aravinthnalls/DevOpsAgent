# AI DevOps Agent

`ai_devops_agent.py` is an autonomous AI agent that scans a codebase, enriches findings with `gpt-4o-mini`, generates CI/CD and infrastructure files, and can support an automated fix PR workflow after merges.

> **OpenAI API token is mandatory.** The agent will not start without one. Provide it via `--openai-token` or the `OPENAI_API_TOKEN` environment variable.

## What this repository contains

- [ai_devops_agent.py](ai_devops_agent.py) — the main agent script
- [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md) — rollout guide for other repositories
- [templates/github-actions/ai-devops-agent-template.yml](templates/github-actions/ai-devops-agent-template.yml) — reusable workflow template
- [templates/pipeline_request.txt.example](templates/pipeline_request.txt.example) — sample configuration

## Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│                         AI DevOps Agent                          │
│                      ai_devops_agent.py                          │
│                                                                  │
│  ┌──────────────────────┐        ┌──────────────────────────┐   │
│  │    CodeAnalyzer      │──────▶ │    PipelineGenerator     │   │
│  │                      │        │                          │   │
│  │ • Frontend scan      │        │ • GitHub Actions CI/CD   │   │
│  │ • Backend scan       │        │ • Terraform (IaC)        │   │
│  │ • Infra scan         │        │ • variables.tf / tfvars  │   │
│  │ • Security scan      │        │ • suggestions.md report  │   │
│  │ • Best practices     │        │ • Dockerfile fixes       │   │
│  │      │               │        │        │                 │   │
│  │      ▼               │        │        ▼                 │   │
│  │ AI Security Enrich   │        │ AI Pipeline & Infra Recs │   │
│  │ (CVEs, exploits,     │        │ (stages, deployment,     │   │
│  │  top 3 actions)      │        │  optimisations, perf)    │   │
│  │      │               │        │        │                 │   │
│  │      ▼               │        │        ▼                 │   │
│  │ AI Best Practices    │        │   File System Writes     │   │
│  │ (maturity, quick     │        │                          │   │
│  │  wins, effort/impact)│        │ .github/workflows/       │   │
│  └──────────────────────┘        │ terraform/               │   │
│           │                      │ frontend/Dockerfile      │   │
│           ▼                      │ backend/Dockerfile       │   │
│  ┌──────────────────────┐        │ suggestions.md           │   │
│  │   OpenAI gpt-4o-mini │        └──────────────────────────┘   │
│  │   (REQUIRED)         │                                        │
│  │                      │                                        │
│  │  3 calls per run:    │                                        │
│  │  1. Security enrich  │                                        │
│  │  2. BP enrich        │                                        │
│  │  3. Pipeline recs    │                                        │
│  └──────────────────────┘                                        │
└──────────────────────────────────────────────────────────────────┘
```

## GitHub Actions integration

```text
Developer opens PR
  │
  ▼
[ai-generate-workflow.yml]
  │
  ├── analyze-and-comment job (PR open/update)
  │       │
  │       ├── python ai_devops_agent.py --analyze-only
  │       ├── python ai_devops_agent.py --suggest-changes
  │       └── Posts AI-enriched suggestions.md as PR comment
  │
  └── create-fix-pr job (PR merged)
    │
    ├── python ai_devops_agent.py          ← full generation
    ├── python ai_devops_agent.py --suggest-changes
    ├── python ai_devops_agent.py --apply-fixes
    ├── git add -A && git diff --cached
    └── Opens "AI Suggestions" PR with all changes
```

## What the agent does

### 1. Code analysis

`CodeAnalyzer` detects:

- frontend framework: `vanilla-js` or Node.js-based layout
- backend language and framework: FastAPI, Flask, Django
- frontend and backend ports
- `requirements.txt`, `package.json`, Dockerfiles, and git metadata

### 2. AI-enriched security scanning

Static checks run first, then findings are enriched by `gpt-4o-mini`.

| Layer | Static checks | AI enrichment |
|---|---|---|
| Frontend | `eval()`, `innerHTML` XSS, hard-coded credentials, missing `package-lock.json` | CVE references, exploit scenario, priority fix |
| Backend | SQL injection, hard-coded secrets, `pickle`, debug mode, missing CORS | CVE references, exploit scenario, priority fix |
| Infrastructure | Root containers, `:latest` tags, committed `.env` files | Attack surface summary, top 3 immediate actions |

Risk levels: `HIGH`, `MEDIUM`, `LOW`.

### 3. AI-enriched best-practices scoring

Static compliance checks are enriched with:

- maturity level: Beginner / Intermediate / Advanced
- quick wins
- prioritised recommendations with effort, impact, and steps

### 4. Infrastructure generation

`PipelineGenerator` writes or updates:

- `.github/workflows/ci-cd.yml`
- `.github/workflows/ai-generate-workflow.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `terraform/outputs.tf`
- `terraform/terraform.tfvars`
- `terraform/user_data.sh`

### 5. Infrastructure fix application

`apply_infra_fixes()` patches Dockerfiles directly.

| Finding | Fix applied |
|---|---|
| Container runs as root | Adds `USER nginx` or `USER appuser` and user creation where needed |
| `:latest` image tag | Replaces with pinned tags such as `nginx:1.25-alpine` and `python:3.11-slim` |

### 6. AI-enriched suggestions report

`suggest_changes()` writes `suggestions.md` with these sections:

1. Security vulnerabilities
2. AI security analysis
3. Structural issues
4. Best-practices recommendations
5. AI best-practices insights
6. AI pipeline and infrastructure recommendations

## OpenAI API calls per run

| Call | Triggered by | System role | Output keys |
|---|---|---|---|
| Security enrichment | `CodeAnalyzer.analyze_project()` | Senior AppSec engineer | `enriched_findings`, `attack_surface_summary`, `top_3_actions` |
| Best-practices enrichment | `CodeAnalyzer.analyze_project()` | DevOps best-practices expert | `prioritised_recommendations`, `maturity_level`, `quick_wins` |
| Pipeline recommendations | `PipelineGenerator._ai_enhance_analysis()` | Expert DevOps engineer | `pipeline_stages`, `testing_strategy`, `deployment_recommendations`, `infra_optimisations`, `performance_tips` |

## CLI usage

```text
# Full pipeline generation (all 3 AI calls + file writes)
python ai_devops_agent.py --openai-token YOUR_TOKEN

# Via environment variable (recommended for CI)
OPENAI_API_TOKEN=your_token python ai_devops_agent.py

# Analyze only — prints AI-enriched report, no file writes
python ai_devops_agent.py --openai-token YOUR_TOKEN --analyze-only

# Verbose — includes raw JSON output
python ai_devops_agent.py --openai-token YOUR_TOKEN --analyze-only --verbose

# Write AI-enriched suggestions.md
python ai_devops_agent.py --openai-token YOUR_TOKEN --suggest-changes

# Apply security fixes to Dockerfiles
python ai_devops_agent.py --openai-token YOUR_TOKEN --apply-fixes

# Generate + auto-commit (used by CI)
python ai_devops_agent.py --openai-token YOUR_TOKEN --auto-commit
```

Without `--openai-token` or `OPENAI_API_TOKEN`, the agent exits immediately with an error.

## Configuration

Example `pipeline_request.txt`:

```text
pipeline_name: qr-generator-auto-pipeline
environment: production
target: aws_ec2
instance_type: t2.micro
ami: latest-ubuntu
deploy_using: docker-compose
labels: [ai-generated, demo, qr-generator]
email_notification: true
email_recipient: demo@example.com
frontend_port: 3000
backend_port: 8000
```

Changes to this file are picked up automatically. `variables.tf` and `terraform.tfvars` are regenerated on every run.

## GitHub secrets required

| Secret | Purpose | Required |
|---|---|---|
| `OPENAI_API_TOKEN` | All AI enrichment and recommendations | Mandatory |
| `PAT_TOKEN` | Create branches and PRs from the workflow | Mandatory |
| `AWS_ACCESS_KEY_ID` | Terraform AWS provider | Mandatory |
| `AWS_SECRET_ACCESS_KEY` | Terraform AWS provider | Mandatory |
| `EMAIL_USERNAME` | Deployment notifications | Optional |
| `EMAIL_PASSWORD` | Deployment notifications | Optional |

## Generated file map

```text
.github/workflows/
├── ci-cd.yml                  ← generated by agent (validate → test → deploy)
└── ai-generate-workflow.yml   ← agent trigger workflow

terraform/
├── main.tf                    ← generated once (EC2 + SG + EIP)
├── variables.tf               ← regenerated on every run from pipeline_request.txt
├── outputs.tf                 ← generated once (includes public_ip, application_urls)
├── terraform.tfvars           ← regenerated on every run from pipeline_request.txt
├── terraform.tfvars.example   ← regenerated alongside tfvars
└── user_data.sh               ← generated once (EC2 bootstrap)

suggestions.md                 ← written by --suggest-changes
frontend/Dockerfile            ← patched by --apply-fixes
backend/Dockerfile             ← patched by --apply-fixes
```

## Dependencies

Python 3.11+ is required.

Required packages:

```text
pyyaml
requests
```

Install with:

```text
pip install pyyaml requests
```

## Using this in another repository

1. Copy [templates/github-actions/ai-devops-agent-template.yml](templates/github-actions/ai-devops-agent-template.yml) to `.github/workflows/ai-devops-agent.yml`.
2. Copy [templates/pipeline_request.txt.example](templates/pipeline_request.txt.example) to `pipeline_request.txt`.
3. Add required secrets, especially `OPENAI_API_TOKEN`, `PAT_TOKEN`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`.
4. The workflow checks out this repository as a second source tree and runs [ai_devops_agent.py](ai_devops_agent.py) from that checked-out path instead of downloading a raw file.
5. Run the workflow in analysis mode first.

For rollout details, see [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).