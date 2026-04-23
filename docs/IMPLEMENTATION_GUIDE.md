# AI DevOps Agent Implementation Guide

This guide reflects the current single-mode AI implementation.

## Overview

The agent now follows one execution path:

1. scan the repository heuristically
2. summarize the scan into structured data
3. send that summary to OpenAI for richer DevOps analysis
4. write `AI_DEVOPS_REPORT.md`
5. generate starter workflow, Compose, Terraform, and generated README assets

## Core Components

- `ProjectAnalyzer`: performs the deterministic repo scan
- `OpenAIEnricher`: calls the OpenAI API and returns structured DevOps guidance
- `PipelineGenerator`: creates starter delivery assets based on the scan
- `AIDevOpsAgent`: runs the single `ai` flow end-to-end

## Repository Scanning Model

The analyzer still performs local detection for:

- frontend technologies including React, Vue, Next.js, static HTML, and server-rendered HTML
- backend technologies including Python, Node, Java, and Go
- IaC signals including Terraform, Kubernetes-style YAML, Helm, Dockerfiles, and Docker Compose
- workflow quality signals from `.github/workflows/*.yml`

That local scan becomes the input context for the AI enrichment step.

## AI Enrichment

The agent requires `OPENAI_API_TOKEN` or `--openai-token`.

It sends the scan summary to OpenAI and asks for JSON containing:

- executive summary
- architecture summary
- frontend assessment
- backend assessment
- IaC recommendations
- workflow review
- security priorities
- quick wins
- long-term improvements
- generated asset guidance

The default model is `gpt-5.4-mini`, configurable with `--openai-model`.

## Execution

There is one supported mode:

```bash
python ai_devops_agent.py --mode ai
```

Examples:

```bash
python ai_devops_agent.py --project-root /path/to/repo --mode ai
python ai_devops_agent.py --openai-model gpt-5.4-mini --mode ai
```

## pipeline_request.txt

`pipeline_request.txt` is optional.

If present, the generator currently uses these keys:

- `pipeline_name`
- `target`
- `environment`
- `instance_type`
- `database_engine`
- `app_image_repository`
- `app_image_tag`

Minimal example:

```txt
pipeline_name: example-service-ai-pipeline
target: aws_ec2
app_image_repository: ghcr.io/example-org/example-app
```

Sensible defaults are used when the file is missing:

- `pipeline_name: devops-pipeline`
- `target: aws_ec2`
- `environment: production`
- `instance_type: t3.micro`

Optional fuller example:

```txt
pipeline_name: example-service-ai-pipeline
target: aws_ec2
environment: production
instance_type: t3.micro
database_engine: postgres
app_image_repository: ghcr.io/example-org/example-app
app_image_tag: latest
```

## Outputs

The run writes:

- `AI_DEVOPS_REPORT.md`
- `.github/workflows/pipeline.yml`
- `docker-compose.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `README_GENERATED.md`

## Sample Requirements File

Use a small, readable `requirements.txt` in the agent repository:

```txt
requests>=2.31,<3.0
PyYAML>=6.0,<7.0
```

If you are documenting target repositories, keep their runtime dependencies separate from the agent's own requirements.

## GitHub Actions Template

The template in `templates/github-actions/ai-devops-agent-template.yml` should:

- install Python dependencies
- provide `OPENAI_API_TOKEN`
- run `python ai_devops_agent.py --mode ai`
- upload `AI_DEVOPS_REPORT.md` and generated artifacts

## Working Workflow Example

The example workflow now matches the working Pet Clinic implementation pattern:

- run on pull request open, sync, reopen, and close
- comment on open PRs with `AI_DEVOPS_REPORT.md`
- support manual `workflow_dispatch`
- optionally create a PR for generated outputs on manual runs
- create a follow-up PR after a merged pull request

Example command used by the workflow:

```bash
python "$AGENT_PATH" \
  --project-root . \
  --config-file pipeline_request.txt \
  --mode ai
```

Required GitHub secrets and variables for the example workflow:

- `OPENAI_API_TOKEN`
- `PAT_TOKEN` for pull request creation
- optional cloud deployment secrets and variables such as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`

## Operational Notes

- The AI output is grounded in the local scan, so detection quality still matters.
- Generated files are starting points, not production-ready final assets.
- Repositories with unusual layouts may still need manual interpretation.
