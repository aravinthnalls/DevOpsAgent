# AI DevOps Agent

`ai_devops_agent.py` scans a repository, identifies the likely frontend and backend stacks, reviews IaC and GitHub Actions, and produces analysis or starter delivery assets.

No OpenAI token is required. The current implementation runs locally with standard Python.

## What It Does

- Scans the full repository instead of assuming only `frontend/` and `backend/`
- Detects likely frontend language/framework and backend language/framework
- Reviews existing Terraform, Kubernetes-style YAML, Helm, Docker, and GitHub Actions
- Produces best-practice suggestions based on the detected application shape
- Generates starter `pipeline.yml`, `docker-compose.yml`, `terraform/`, and `README_GENERATED.md`

## Architecture

```text
ProjectAnalyzer          WorkflowOrchestrator          PipelineGenerator
    ↓                           ↓                             ↓
Repo-wide scanning       analyze-only mode            GitHub Actions workflow
Frontend/backend ID      suggest-changes mode         Docker Compose config
IaC + workflow review    generate-and-commit mode     Terraform infrastructure
Security checks          generate mode                Generated documentation
```

## Quick Start

```bash
python ai_devops_agent.py --mode analyze-only
python ai_devops_agent.py --mode suggest-changes
python ai_devops_agent.py --mode generate
```

## Detection Coverage

The analyzer currently looks for:

- Frontend stacks such as React, Next.js, Vue, Angular, Svelte, and static web apps
- Backend stacks such as Python services, Node/Nest/Express services, Java services, and Go services
- Existing IaC including Terraform, Kubernetes-like manifests, Helm charts, Docker Compose, and Dockerfiles
- GitHub Actions workflow quality issues such as unsupported agent flags, stale artifact names, and missing test steps

## Output Files

Depending on mode, the agent can create:

- `.github/workflows/pipeline.yml`
- `docker-compose.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `README_GENERATED.md`
- `SUGGESTIONS.md`

## Modes

| Mode | Purpose |
|---|---|
| `analyze-only` | Print repo analysis only |
| `suggest-changes` | Write `SUGGESTIONS.md` with findings and recommendations |
| `generate` | Generate starter delivery files |
| `generate-and-commit` | Generate files and commit them if git is available |

Backward-compatible flags still work:

```bash
python ai_devops_agent.py --analyze-only
python ai_devops_agent.py --suggest-changes
python ai_devops_agent.py --auto-commit
```

## Configuration

Optional `pipeline_request.txt` example:

```yaml
pipeline_name: my-service-pipeline
environment: production
target: aws_ec2
instance_type: t3.micro
frontend_port: 3000
backend_port: 8000
```

## GitHub Actions Integration

Use the template at [templates/github-actions/ai-devops-agent-template.yml](templates/github-actions/ai-devops-agent-template.yml).

Important current expectations:

- Use supported modes only: `analyze-only`, `suggest-changes`, `generate`, `generate-and-commit`
- Expect the suggestions artifact to be `SUGGESTIONS.md`
- Prefer pinning the agent source repo to a tag or commit SHA rather than `main`

## Requirements

- Python 3.9+

Optional dev tools:

- `pytest`
- `ruff`
- `mypy`

## Notes

- Generated Terraform is a starting point and should be reviewed before apply.
- Generated workflows are starter pipelines and should be adapted to the target repository.
- Detection is heuristic-based, so unusual repository layouts may need manual review.

## Support

Implementation details and rollout guidance live in [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).
