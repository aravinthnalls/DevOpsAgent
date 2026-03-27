# AI DevOps Agent (Simplified)

`ai_devops_agent.py` is a straightforward DevOps automation tool that analyzes your codebase and generates production-ready CI/CD pipelines and infrastructure code.

**No OpenAI token required** — The agent works standalone. Optional AI enrichment available via `--openai-token`.

## What this repository contains

- [ai_devops_agent.py](ai_devops_agent.py) — Single-file DevOps agent with Python workflow orchestration
- [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md) — Usage guide and examples
- [templates/](templates/) — Example configurations

## Architecture

```
ProjectAnalyzer          WorkflowOrchestrator          PipelineGenerator
    ↓                           ↓                             ↓
Frontend detection    analyze-only mode            GitHub Actions workflow
Backend detection     generate mode                Docker Compose config
Security scanning     suggest-changes mode        Terraform infrastructure
Git analysis          generate-and-commit mode    Documentation
```

All components run in Python — no complex YAML orchestration needed!

## Quick Start

```bash
# Install dependencies
python -m pip install -r requirements.txt

# Analyze your project
python ai_devops_agent.py --mode analyze-only

# Generate CI/CD pipeline
python ai_devops_agent.py --mode generate

# Generate and commit changes
python ai_devops_agent.py --mode generate-and-commit

# Get suggestions report
python ai_devops_agent.py --mode suggest-changes
```

## What the agent generates

✅ **CI/CD Pipeline** - `.github/workflows/pipeline.yml`
- Dependency installation
- Test execution
- Docker image building
- AWS deployment

✅ **Infrastructure as Code** - `terraform/`
- AWS EC2 instance configuration
- Security groups
- Output variables

✅ **Container Configuration** - `docker-compose.yml`
- Frontend service
- Backend service
- Networking setup

✅ **Documentation** - `README_GENERATED.md`
- Project overview
- Security findings
- Deployment instructions

## Project Detection

The agent automatically detects:

- **Frontend**: React, Vue, Angular, Next.js, or vanilla HTML/CSS/JS
- **Backend**: FastAPI, Flask, Django, or generic Python
- **Services**: Port numbers, dependencies, frameworks
- **Infrastructure**: Existing Terraform, Docker, git repositories
- **Security Issues**: Common vulnerabilities in code and configuration

## Workflow Modes

The agent runs in different modes depending on your use case:

| Mode | Purpose | Use Case |
|---|---|---|
| `analyze-only` | Scan and report without generating files | PR analysis, security review |
| `generate` (default) | Generate complete pipeline | Initial setup, updates |
| `generate-and-commit` | Generate and commit to git | CI/CD automation |
| `suggest-changes` | Create suggestions markdown report | Documentation, reviews |

## Installation & Setup

```bash
# Clone this repository
git clone <repo-url>

# Install dependencies
python -m pip install -r requirements.txt

# Optional: install dev tools (pytest, ruff, mypy)
python -m pip install -r requirements-dev.txt

# Copy agent to your project or reference it
cp ai_devops_agent.py /path/to/your/project/

# Add pipeline config (optional)
cp templates/pipeline_request.txt.example pipeline_request.txt
```

## Usage Examples

### Local Development

```bash
# Analyze your project
python ai_devops_agent.py --project-root . --mode analyze-only

# Generate pipeline
python ai_devops_agent.py --project-root . --mode generate
```

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: Generate DevOps Pipeline
  run: |
    python -m pip install -r requirements.txt
    python ai_devops_agent.py --mode generate-and-commit
```

**GitLab CI:**
```yaml
generate_pipeline:
  script:
    - python -m pip install -r requirements.txt
    - python ai_devops_agent.py --mode generate
```

### Docker

```bash
docker run -v $(pwd):/app python:3.11 bash -c \
  "cd /app && python -m pip install -r requirements.txt && python ai_devops_agent.py"
```

## Configuration File

Create `pipeline_request.txt` in your project root:

```yaml
pipeline_name: my-awesome-app
environment: production
target: aws_ec2
instance_type: t3.micro
frontend_port: 3000
backend_port: 8000
```

All settings have sensible defaults, so the file is optional.

## Output Files

After running, check these files:

```
├── .github/workflows/pipeline.yml       ← GitHub Actions CI/CD
├── docker-compose.yml                   ← Local development
├── terraform/
│   ├── main.tf                          ← EC2 resources
│   └── variables.tf                     ← Configuration
├── README_GENERATED.md                  ← Generated docs
└── SUGGESTIONS.md                       ← (if using suggest-changes mode)
```

## CLI Reference

```bash
# Show all options
python ai_devops_agent.py --help

# Analyze current directory
python ai_devops_agent.py

# Analyze specific project
python ai_devops_agent.py --project-root /path/to/project

# Use custom config file
python ai_devops_agent.py --config-file custom-config.txt

# Enable verbose output
python ai_devops_agent.py --verbose

# Use OpenAI token for future enhancements
python ai_devops_agent.py --openai-token YOUR_TOKEN_HERE
```

## Project Requirements

The agent works best with projects that have:

```
project/
├── frontend/               (optional: Node.js or static HTML)
│   ├── package.json
│   └── src/
├── backend/                (optional: Python)
│   ├── requirements.txt
│   └── main.py
├── Dockerfile              (optional)
├── docker-compose.yml      (optional)
└── pipeline_request.txt    (optional)
```

If your project structure is different, the agent will still work but may need manual adjustments to generated files.

## Dependencies

- Python 3.9+
- `pyyaml`
- `requests`

## License

MIT

## Contributing

Contributions welcome! Areas for improvement:

- [ ] Support for more languages (Go, Node.js, Java)
- [ ] Additional CI/CD platforms (GitLab CI, CircleCI, etc.)
- [ ] More infrastructure targets (Kubernetes, GCP, Azure)
- [ ] Enhanced security scanning
- [ ] Cost optimization analysis

## Support

For issues or suggestions, open an issue in this repository.

For rollout details, see [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).