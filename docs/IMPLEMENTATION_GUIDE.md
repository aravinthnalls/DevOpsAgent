# AI DevOps Agent Implementation Guide

This guide reflects the current simplified agent behavior.

## Overview

The agent is a single Python entrypoint with three main responsibilities:

- `ProjectAnalyzer`: scan the full repository, identify likely application components, inspect IaC, inspect workflows, and flag risks
- `PipelineGenerator`: generate starter workflow, Compose, Terraform, and generated documentation
- `WorkflowOrchestrator`: expose the execution modes and write the final reports

## Repository Scanning Model

The analyzer no longer depends on a strict `frontend/` and `backend/` layout.

It searches the repository for signals such as:

- `package.json`, `index.html`, JS/TS source files for frontend detection
- `requirements.txt`, `pyproject.toml`, Python source, `go.mod`, `pom.xml`, `build.gradle`, Node server packages for backend detection
- Terraform files, Kubernetes-style YAML, Helm charts, Dockerfiles, Docker Compose, and `.github/workflows/*.yml`

The output is heuristic. Repositories with unusual layouts can still be analyzed, but the results should be reviewed manually.

## Execution Modes

### Analyze Only

```bash
python ai_devops_agent.py --mode analyze-only
```

Prints a repo summary including:

- files scanned
- top languages
- frontend/backend detection
- IaC/workflow counts
- security summary
- GitHub Actions drift findings

### Suggest Changes

```bash
python ai_devops_agent.py --mode suggest-changes
```

Writes `SUGGESTIONS.md` containing:

- repo summary
- frontend/backend findings
- IaC review
- GitHub Actions review
- security findings
- best-practice strengths, gaps, and actions

### Generate

```bash
python ai_devops_agent.py --mode generate
```

Generates starter assets:

- `.github/workflows/pipeline.yml`
- `docker-compose.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `README_GENERATED.md`

### Generate And Commit

```bash
python ai_devops_agent.py --mode generate-and-commit
```

Runs generation, then attempts a git commit.

## Workflow Template Expectations

The template in `templates/github-actions/ai-devops-agent-template.yml` is the source of truth for workflow integration.

The workflow should:

- install Python and agent dependencies if needed
- run `--mode analyze-only` for PR analysis
- run `--mode suggest-changes` to produce `SUGGESTIONS.md`
- use only supported modes in `workflow_dispatch`
- avoid calling unsupported flags like `--apply-fixes`

## Known Drift That Was Corrected

Older workflow and documentation examples in downstream repos used stale behavior:

- `generate-pipeline` instead of `generate`
- `--apply-fixes`, which is not supported
- `suggestions.md` instead of `SUGGESTIONS.md`
- references to generated files that this simplified agent does not create

If a target repository still uses those older names, update it to the current template.

## Configuration

Optional `pipeline_request.txt`:

```yaml
pipeline_name: my-service-pipeline
environment: production
target: aws_ec2
instance_type: t3.micro
frontend_port: 3000
backend_port: 8000
```

## Rollout Guidance

### Phase 1

Run `analyze-only` and `suggest-changes` in pull requests.

Validate:

- frontend/backend detection quality
- workflow findings
- IaC findings
- usefulness of best-practice suggestions

### Phase 2

Enable manual `generate` runs through `workflow_dispatch`.

Validate:

- generated workflow commands
- generated Compose paths
- generated Terraform ports and ingress rules
- generated README summary

### Phase 3

Adopt `generate-and-commit` only after the generated outputs are trusted for the target repositories.

## Review Checklist

- confirm the detected frontend path is correct
- confirm the detected backend path is correct
- review any workflow findings before trusting automation
- treat generated Terraform as a baseline, not production-ready IaC
- verify ports and deployment assumptions against the actual application
