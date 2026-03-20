# AI DevOps Agent Implementation Guide

This guide explains how to implement the agent from this repository in another repository with the same pull-request analysis and post-merge fix PR pattern described by the agent design.

## Adoption model

Recommended model:

1. keep this repository as the source of truth
2. check out this repository during workflow execution into a tools path
3. run it against the checked-out target repository
4. publish `suggestions.md` on pull requests
5. after merge, run generation and open a fix PR automatically

That flow is implemented in [templates/github-actions/ai-devops-agent-template.yml](../templates/github-actions/ai-devops-agent-template.yml).

## Target repository expectations

Best results come from repositories with:

- `frontend/` for frontend application code
- `backend/` for Python backend code
- `pipeline_request.txt` for generation settings

If the structure differs, analysis and generated outputs may need manual adjustment.

## Mandatory runtime requirement

The agent requires an OpenAI token on every execution path.

Supported injection methods:

- `--openai-token`
- `OPENAI_API_TOKEN`

Without one, the agent exits immediately.

## Source code reference model

The workflow template does not download a raw Python file.

Instead, it checks out this repository as a second working tree inside the target repository workflow run and executes [ai_devops_agent.py](../ai_devops_agent.py) from that checked-out path.

Default layout inside the workflow runner:

```text
.
├── <target repository>
└── .github/tools/devops-agent-source/
	└── ai_devops_agent.py
```

This makes the implementation easier to audit and lets you pin the full source repository by branch, tag, or commit SHA.

## Required secrets in the target repository

| Secret | Purpose | Required |
|---|---|---|
| `OPENAI_API_TOKEN` | AI enrichment and recommendations | Mandatory |
| `PAT_TOKEN` | Create comments, branches, and fix PRs | Mandatory |
| `AWS_ACCESS_KEY_ID` | Terraform deployment workflow output | Mandatory |
| `AWS_SECRET_ACCESS_KEY` | Terraform deployment workflow output | Mandatory |
| `EMAIL_USERNAME` | Deployment notifications | Optional |
| `EMAIL_PASSWORD` | Deployment notifications | Optional |

## Files to copy into the target repository

### Workflow template

Copy [templates/github-actions/ai-devops-agent-template.yml](../templates/github-actions/ai-devops-agent-template.yml) to `.github/workflows/ai-devops-agent.yml`.

### Pipeline configuration

Copy [templates/pipeline_request.txt.example](../templates/pipeline_request.txt.example) to `pipeline_request.txt`.

Suggested starting point:

```text
pipeline_name: my-service-ai-pipeline
environment: production
target: aws_ec2
instance_type: t3.micro
ami: latest-ubuntu
deploy_using: docker-compose
frontend_port: 3000
backend_port: 8000
labels: [ai-generated, devops-agent]
email_notification: false
email_recipient: platform@example.com
```

## Workflow behavior

### Pull request path

On pull request open or update, the workflow:

- checks out the PR branch
- checks out this repository into `.github/tools/devops-agent-source`
- installs `requests` and `PyYAML`
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