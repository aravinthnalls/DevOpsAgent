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

## Outputs

The run writes:

- `AI_DEVOPS_REPORT.md`
- `.github/workflows/pipeline.yml`
- `docker-compose.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `README_GENERATED.md`

## GitHub Actions Template

The template in `templates/github-actions/ai-devops-agent-template.yml` should:

- install Python dependencies
- provide `OPENAI_API_TOKEN`
- run `python ai_devops_agent.py --mode ai`
- upload `AI_DEVOPS_REPORT.md` and generated artifacts

## Operational Notes

- The AI output is grounded in the local scan, so detection quality still matters.
- Generated files are starting points, not production-ready final assets.
- Repositories with unusual layouts may still need manual interpretation.
