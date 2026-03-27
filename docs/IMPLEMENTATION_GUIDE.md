# AI DevOps Agent Implementation Guide

**Simplified Version** — All workflow logic is now in Python!

This guide explains how to use the streamlined agent. The implementation is straightforward: a Python script with workflow orchestration modes instead of complex GitHub Actions templates.

## Architecture Overview

The agent is organized into clear, focused Python components:

- **ProjectAnalyzer** - Analyzes project structure, frameworks, and security
- **PipelineGenerator** - Generates CI/CD files and infrastructure code  
- **WorkflowOrchestrator** - Manages execution modes (analyze, generate, suggest, etc.)

All workflow logic runs in Python - no complex GitHub Actions orchestration needed.

## Target repository expectations

Best results come from repositories with:

- `frontend/` for frontend application code (Node.js, React, Vue, etc.)
- `backend/` for Python backend code (FastAPI, Flask, Django, etc.)  
- `pipeline_request.txt` for generation settings (optional)

## Installation

Copy `ai_devops_agent.py` to your repository or reference it from this source repository.

### Requirements

```bash
python -m pip install -r requirements.txt
# Optional: install development tooling
python -m pip install -r requirements-dev.txt
python >= 3.9
```

## Usage

## Required secrets in the target repository

| Secret | Purpose | Required |
|---|---|---|
| `OPENAI_API_TOKEN` | AI enrichment (future use) | Optional |

## Execution Modes

The agent supports multiple execution modes:

### 1. Analyze Only
Scan the project and display findings:
```bash
python ai_devops_agent.py --mode analyze-only
```

### 2. Generate Pipeline (Default)
Generate all CI/CD and infrastructure files:
```bash
python ai_devops_agent.py
# or
python ai_devops_agent.py --mode generate
```

### 3. Generate and Commit
Generate files and automatically commit:
```bash
python ai_devops_agent.py --mode generate-and-commit
```

### 4. Suggest Changes
Create a suggestions report:
```bash
python ai_devops_agent.py --mode suggest-changes
```

## Configuration

Create `pipeline_request.txt` in your project root:

```yaml
pipeline_name: my-service-pipeline
environment: production
target: aws_ec2
instance_type: t3.micro
frontend_port: 3000
backend_port: 8000
```

## What Gets Generated

The agent creates:

1. **`.github/workflows/pipeline.yml`** - Ready-to-use CI/CD pipeline
   - Installs dependencies
   - Runs tests  
   - Builds Docker image
   - Deploys to AWS

2. **`docker-compose.yml`** - Local development environment
   - Spins up frontend + backend services
   - Configures networking and ports

3. **`terraform/`** - Infrastructure as Code
   - AWS EC2 instance configuration
   - Security groups
   - Auto-detection of Ubuntu AMI

4. **`README_GENERATED.md`** - Documentation
   - Project overview
   - Quick start instructions
   - Security findings
   - Deployment steps

## Workflow Benefits

✅ **Simple** - Single Python file, no complex orchestration
✅ **Fast** - Generates complete pipelines in seconds
✅ **Modular** - Easy to extend or customize
✅ **Type-safe** - Python type hints throughout
✅ **Flexible** - Run locally or in any CI/CD system

## Integration Examples

### Run locally
```bash
python ai_devops_agent.py --project-root /path/to/project
```

### Use in GitHub Actions
```yaml
- name: Run AI DevOps Agent
  run: python ai_devops_agent.py --mode generate-and-commit
```

### Use in GitLab CI
```yaml
ai_devops_agent:
  script:
    - pip install -q pyyaml requests
    - python ai_devops_agent.py --mode suggest-changes
```
- runs `python ai_devops_agent.py --analyze-only`
- runs `python ai_devops_agent.py --suggest-changes`
- uploads artifacts
- posts `suggestions.md` back to the pull request

### Post-merge path

When a pull request is merged, the workflow:

- checks out `main`
- checks out this repository into `.github/tools/devops-agent-source`
- runs full generation
- runs `--suggest-changes`
- runs `--apply-fixes`
- checks for changes
- creates a new branch
- opens an "AI Suggestions" pull request

## Recommended rollout sequence

### Phase 1: Analysis only

Start with pull requests only.

Validate:

- repository detection
- quality of `suggestions.md`
- accuracy of AI-enriched security findings

### Phase 2: Controlled generation

Enable the merge-triggered fix PR flow only after review.

Validate:

- generated workflow files
- Terraform outputs
- Dockerfiles
- README updates

### Phase 3: Production hardening

After adoption:

- refine `pipeline_request.txt`
- narrow security group ingress rules
- review generated Terraform before apply
- adjust generated CI/CD for environment-specific needs

## OpenAI calls executed by the agent

Per normal full run, the agent makes three model calls:

1. security enrichment
2. best-practices enrichment
3. pipeline and infrastructure recommendations

Outputs include CVE context, exploit scenarios, priority fixes, maturity level, quick wins, testing strategy, deployment recommendations, infrastructure optimisations, and performance tips.

## What to review before merge

Review these outputs carefully:

- `.github/workflows/ci-cd.yml`
- `.github/workflows/ai-generate-workflow.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `terraform/outputs.tf`
- `terraform/terraform.tfvars`
- `terraform/user_data.sh`
- `frontend/Dockerfile`
- `backend/Dockerfile`
- `suggestions.md`
- `README.md`

## Operational cautions

- Pin the source repository to a release tag or commit SHA instead of `main`.
- Do not allow direct generation pushes to protected branches.
- Treat generated Terraform as a starting point, not final production IaC.
- Review Dockerfile fixes before deployment.
- Review README output because current generation text can be project-specific.

## Quick checklist

- [ ] add `OPENAI_API_TOKEN`
- [ ] add `PAT_TOKEN`
- [ ] add AWS credentials if generated deployment workflows will be used
- [ ] copy workflow into `.github/workflows/`
- [ ] copy `pipeline_request.txt`
- [ ] validate PR analysis output
- [ ] validate post-merge fix PR creation
- [ ] review generated infrastructure before applying changes