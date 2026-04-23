# AI DevOps Agent

`ai_devops_agent.py` now runs in a single AI-driven mode. It scans a repository, builds a structured repo summary, sends that summary to OpenAI for richer DevOps analysis, and then writes a report plus starter delivery assets.

## What It Does

- Detects likely frontend and backend stacks across the full repo
- Reviews Docker, IaC, and GitHub Actions
- Uses OpenAI to generate richer architecture, workflow, security, and IaC guidance
- Writes `AI_DEVOPS_REPORT.md`
- Generates starter `.github/workflows/pipeline.yml`, `docker-compose.yml`, `terraform/`, and `README_GENERATED.md`

## Requirements

- Python 3.9+
- `OPENAI_API_TOKEN`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

There is one supported mode:

```bash
python ai_devops_agent.py --mode ai
```

Optional flags:

```bash
python ai_devops_agent.py --project-root /path/to/repo --mode ai
python ai_devops_agent.py --openai-model gpt-5.4-mini --mode ai
```

If `--openai-token` is not passed, the agent reads `OPENAI_API_TOKEN`.

## Output Files

- `AI_DEVOPS_REPORT.md`
- `.github/workflows/pipeline.yml`
- `docker-compose.yml`
- `terraform/main.tf`
- `terraform/variables.tf`
- `README_GENERATED.md`

## AI Usage

The agent uses a real OpenAI API call to enrich the heuristic repo scan with:

- executive summary
- architecture assessment
- frontend and backend assessments
- IaC recommendations
- workflow review notes
- security priorities
- quick wins and longer-term improvements

The default model is `gpt-5.4-mini`, configurable with `--openai-model`.

## GitHub Actions

Use the template at [templates/github-actions/ai-devops-agent-template.yml](templates/github-actions/ai-devops-agent-template.yml).

The workflow should:

- provide `OPENAI_API_TOKEN`
- run `python ai_devops_agent.py --mode ai`
- upload `AI_DEVOPS_REPORT.md`

## Notes

- Detection is still heuristic; AI enriches the findings but does not replace repository-specific review.
- Generated Terraform and workflows are starting points and should be reviewed before production use.
- Server-rendered HTML apps are treated as frontend surfaces even when they live inside the backend codebase.

## Support

Implementation details live in [docs/IMPLEMENTATION_GUIDE.md](docs/IMPLEMENTATION_GUIDE.md).
