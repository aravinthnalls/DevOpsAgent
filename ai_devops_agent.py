#!/usr/bin/env python3
"""
AI DevOps Agent
===============

A lightweight DevOps analysis and generation tool that:
- scans the full repository instead of assuming fixed frontend/backend folders
- detects frontend/backend languages, frameworks, and likely entry points
- reviews existing infrastructure-as-code and GitHub Actions workflows
- highlights security and best-practice gaps
- can generate starter CI/CD, Docker Compose, Terraform, and documentation
"""

from __future__ import annotations

import argparse
import json
import os
import re
import requests
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


IGNORED_DIRS = {
    ".git",
    ".github/tools",
    ".idea",
    ".next",
    ".terraform",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "venv",
}


TEXT_FILE_EXTENSIONS = {
    ".css",
    ".go",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".py",
    ".rb",
    ".sh",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

PORT_SCAN_EXTENSIONS = {
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".py",
    ".sh",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}


try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None


@dataclass
class ComponentCandidate:
    path: Path
    score: int
    language: str
    framework: str
    kind: str


class ProjectAnalyzer:
    """Analyzes project structure, languages, workflows, IaC, and security."""

    def __init__(self, project_root: str, openai_token: Optional[str] = None):
        self.project_root = Path(project_root).resolve()
        self.openai_token = openai_token
        self.results: Dict = {}

    def analyze(self) -> Dict:
        """Run complete project analysis."""
        print("Analyzing repository...")

        repo_summary = self._analyze_repository()
        frontend = self._analyze_frontend()
        backend = self._analyze_backend()
        if frontend.get("exists") and frontend.get("type") == "spring-static" and backend.get("exists"):
            frontend["port"] = backend.get("port", frontend.get("port"))
        infrastructure = self._analyze_infrastructure(frontend, backend)
        docker = self._analyze_docker()
        git = self._analyze_git()
        github_actions = self._analyze_github_actions()
        security = self._analyze_security(frontend, backend, infrastructure)
        best_practices = self._analyze_best_practices(
            repo_summary, frontend, backend, infrastructure, docker, github_actions
        )

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "project_root": str(self.project_root),
            "repository": repo_summary,
            "frontend": frontend,
            "backend": backend,
            "infrastructure": infrastructure,
            "docker": docker,
            "git": git,
            "github_actions": github_actions,
            "security": security,
            "best_practices": best_practices,
        }
        return self.results

    def _walk_files(self) -> Iterable[Path]:
        for root, dirs, files in os.walk(self.project_root):
            dirs[:] = [
                d for d in dirs
                if d not in IGNORED_DIRS
                and not d.startswith(".cache")
            ]
            root_path = Path(root)
            for name in files:
                yield root_path / name

    def _safe_read_text(self, path: Path, max_chars: int = 200000) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
        except Exception:
            return ""

    def _relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return str(path)

    def _analyze_repository(self) -> Dict:
        files = list(self._walk_files())
        language_counter: Counter[str] = Counter()
        important_files: List[str] = []

        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".kt": "kotlin",
            ".go": "go",
            ".rb": "ruby",
            ".tf": "terraform",
            ".yml": "yaml",
            ".yaml": "yaml",
            ".sh": "shell",
            ".html": "html",
            ".css": "css",
        }

        for file in files:
            if file.name in {"package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", "build.gradle"}:
                important_files.append(self._relative(file))
            language = extension_map.get(file.suffix.lower())
            if language:
                language_counter[language] += 1

        return {
            "file_count": len(files),
            "top_languages": dict(language_counter.most_common(8)),
            "important_files": sorted(important_files)[:30],
        }

    def _analyze_frontend(self) -> Dict:
        candidates: List[ComponentCandidate] = []

        for package_file in self.project_root.rglob("package.json"):
            if self._is_ignored(package_file):
                continue
            package_data = self._load_json(package_file)
            if not package_data:
                continue

            deps = self._combined_dependencies(package_data)
            framework = self._detect_js_framework(package_data)
            score = 0
            path_text = self._relative(package_file.parent).lower()

            if framework in {"react", "vue", "angular", "nextjs", "svelte"}:
                score += 5
            if any(name in path_text for name in ("frontend", "client", "web", "ui", "app")):
                score += 3
            if "vite" in deps or "webpack" in deps or "parcel" in deps:
                score += 2
            if any(script in package_data.get("scripts", {}) for script in ("start", "dev", "build")):
                score += 2
            if any(server_dep in deps for server_dep in ("express", "koa", "fastify", "@nestjs/core")):
                score -= 4

            if score > 0:
                candidates.append(
                    ComponentCandidate(
                        path=package_file.parent,
                        score=score,
                        language="typescript" if self._has_typescript_sources(package_file.parent) else "javascript",
                        framework=framework,
                        kind="nodejs",
                    )
                )

        for html_file in self.project_root.rglob("index.html"):
            if self._is_ignored(html_file):
                continue
            path_text = self._relative(html_file.parent).lower()
            score = 3
            if any(name in path_text for name in ("frontend", "client", "web", "ui")):
                score += 2
            candidates.append(
                ComponentCandidate(
                    path=html_file.parent,
                    score=score,
                    language="html-css-js",
                    framework="static",
                    kind="static",
                )
            )

        spring_template_dir = self.project_root / "src" / "main" / "resources" / "templates"
        spring_static_dir = self.project_root / "src" / "main" / "resources" / "static"
        if spring_template_dir.exists() or spring_static_dir.exists():
            score = 6
            if spring_template_dir.exists():
                score += 2
            if spring_static_dir.exists():
                score += 2
            candidates.append(
                ComponentCandidate(
                    path=spring_template_dir if spring_template_dir.exists() else spring_static_dir,
                    score=score,
                    language="html-css-js",
                    framework="server-rendered-html",
                    kind="spring-static",
                )
            )

        if not candidates:
            return {"exists": False}

        best = max(candidates, key=lambda item: (item.score, -len(item.path.parts)))
        package_file = best.path / "package.json"
        package_data = self._load_json(package_file) if package_file.exists() else {}
        html_templates = list(best.path.rglob("*.html")) if best.path.exists() else []
        static_assets = [
            self._relative(path)
            for path in (self.project_root / "src" / "main" / "resources" / "static").rglob("*")
            if path.is_file() and not self._is_ignored(path)
        ] if best.kind == "spring-static" else []
        frontend_port = self._detect_port(self.project_root if best.kind == "spring-static" else best.path, 3000)

        return {
            "exists": True,
            "path": self._relative(best.path),
            "type": best.kind,
            "language": best.language,
            "framework": best.framework,
            "port": frontend_port,
            "scripts": package_data.get("scripts", {}),
            "dependencies": sorted(self._combined_dependencies(package_data).keys())[:25],
            "template_count": len(html_templates),
            "template_examples": [self._relative(path) for path in html_templates[:8]],
            "static_asset_examples": static_assets[:8],
            "evidence": self._collect_frontend_evidence(best.path, best.kind, package_data),
        }

    def _analyze_backend(self) -> Dict:
        candidates: List[ComponentCandidate] = []

        for file in self._walk_files():
            rel = self._relative(file).lower()
            parent = file.parent

            if file.name in {"requirements.txt", "pyproject.toml"}:
                if not self._looks_like_python_service(parent) and not any(
                    name in rel for name in ("backend", "api", "server", "service")
                ):
                    continue
                framework = self._detect_python_framework(parent)
                score = 6 if "backend" in rel or "api" in rel or "server" in rel else 4
                candidates.append(ComponentCandidate(parent, score, "python", framework, "service"))
            elif file.suffix == ".py" and file.parent != self.project_root:
                content = self._safe_read_text(file, 12000).lower()
                if any(token in content for token in ("fastapi", "flask", "django", "uvicorn", "gunicorn")):
                    framework = self._detect_python_framework(parent)
                    score = 5 if "backend" in rel or "api" in rel or "server" in rel else 3
                    candidates.append(ComponentCandidate(parent, score, "python", framework, "service"))
            elif file.name == "package.json":
                package_data = self._load_json(file)
                deps = self._combined_dependencies(package_data)
                if any(dep in deps for dep in ("express", "koa", "fastify", "@nestjs/core")):
                    framework = self._detect_node_backend_framework(package_data)
                    score = 6 if "backend" in rel or "api" in rel or "server" in rel else 4
                    candidates.append(
                        ComponentCandidate(
                            parent,
                            score,
                            "typescript" if self._has_typescript_sources(parent) else "javascript",
                            framework,
                            "service",
                        )
                    )
            elif file.name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
                framework = self._detect_java_framework(parent)
                score = 5 if "backend" in rel or "api" in rel or "service" in rel else 3
                candidates.append(ComponentCandidate(parent, score, "java", framework, "service"))
            elif file.name == "go.mod":
                framework = self._detect_go_framework(parent)
                score = 5 if "backend" in rel or "api" in rel or "service" in rel else 3
                candidates.append(ComponentCandidate(parent, score, "go", framework, "service"))

        if not candidates:
            return {"exists": False}

        best = max(candidates, key=lambda item: (item.score, -len(item.path.parts)))
        dependencies: List[str] = []
        if (best.path / "requirements.txt").exists():
            dependencies = self._read_requirements(best.path / "requirements.txt")
        elif (best.path / "package.json").exists():
            dependencies = sorted(self._combined_dependencies(self._load_json(best.path / "package.json")).keys())[:25]
        elif (best.path / "pom.xml").exists():
            dependencies = self._extract_xml_artifact_ids(best.path / "pom.xml")
        elif (best.path / "build.gradle").exists():
            dependencies = self._extract_gradle_dependencies(best.path / "build.gradle")
        elif (best.path / "build.gradle.kts").exists():
            dependencies = self._extract_gradle_dependencies(best.path / "build.gradle.kts")

        tests = self._discover_tests(best.path, best.language)
        databases = self._detect_datastores(best.path)
        build_files = [
            self._relative(best.path / name)
            for name in ("pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml", "package.json", "go.mod")
            if (best.path / name).exists()
        ]
        runtime = self._detect_runtime(best.path, best.language)

        return {
            "exists": True,
            "path": self._relative(best.path),
            "type": best.kind,
            "language": best.language,
            "framework": best.framework,
            "port": self._detect_port(best.path, 8080 if best.language == "java" else 8000),
            "dependencies": dependencies,
            "build_files": build_files,
            "tests": tests,
            "datastores": databases,
            "runtime": runtime,
            "entrypoints": self._find_backend_entrypoints(best.path, best.language),
        }

    def _analyze_infrastructure(self, frontend: Dict, backend: Dict) -> Dict:
        terraform_files = [
            self._relative(path)
            for path in self.project_root.rglob("*.tf")
            if not self._is_ignored(path)
        ]
        kubernetes_files = [
            self._relative(path)
            for path in self._find_yaml_with_markers(("kind:", "apiVersion:"))
            if not self._is_ignored(path)
        ]
        helm_charts = [
            self._relative(path.parent)
            for path in self.project_root.rglob("Chart.yaml")
            if not self._is_ignored(path)
        ]
        ansible_files = [
            self._relative(path)
            for path in self.project_root.rglob("*.yml")
            if not self._is_ignored(path) and "ansible" in self._safe_read_text(path, 4000).lower()
        ]
        cloudformation_files = [
            self._relative(path)
            for path in self._find_yaml_with_markers(("Resources:", "AWSTemplateFormatVersion"))
            if not self._is_ignored(path)
        ]
        db_init_files = [
            self._relative(path)
            for path in self.project_root.rglob("*.sql")
            if not self._is_ignored(path)
        ]
        compose_services = self._parse_compose_services()

        suggestions: List[str] = []
        if backend.get("exists") and not terraform_files and not kubernetes_files and not helm_charts:
            suggestions.append("Backend detected but no Terraform, Kubernetes, or Helm configuration was found.")
        if frontend.get("exists") and backend.get("exists") and not (self.project_root / "docker-compose.yml").exists():
            suggestions.append("Full-stack app detected without docker-compose.yml for local orchestration.")
        if compose_services and backend.get("exists") and backend.get("framework") == "spring-boot":
            suggestions.append("Existing docker-compose services suggest database dependencies that should be reflected in generated IaC.")

        return {
            "terraform_exists": bool(terraform_files),
            "terraform_files": terraform_files,
            "kubernetes_files": kubernetes_files,
            "helm_charts": sorted(set(helm_charts)),
            "ansible_files": ansible_files,
            "cloudformation_files": cloudformation_files,
            "db_init_files": db_init_files[:20],
            "compose_services": compose_services,
            "suggestions": suggestions,
        }

    def _analyze_docker(self) -> Dict:
        dockerfiles = [
            self._relative(path)
            for path in self.project_root.rglob("Dockerfile")
            if not self._is_ignored(path)
        ]
        compose_files = [
            self._relative(path)
            for path in self.project_root.rglob("docker-compose*.yml")
            if not self._is_ignored(path)
        ]
        compose_files.extend(
            self._relative(path)
            for path in self.project_root.rglob("docker-compose*.yaml")
            if not self._is_ignored(path)
        )
        return {
            "dockerfiles": sorted(set(dockerfiles)),
            "compose_files": sorted(set(compose_files)),
            "compose_exists": bool(compose_files),
        }

    def _analyze_git(self) -> Dict:
        git_dir = self.project_root / ".git"
        if not git_dir.exists():
            return {"is_repo": False}

        result = {"is_repo": True}
        try:
            result["branch"] = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        except Exception:
            pass
        return result

    def _analyze_github_actions(self) -> Dict:
        workflow_dir = self.project_root / ".github" / "workflows"
        if not workflow_dir.exists():
            return {
                "exists": False,
                "workflows": [],
                "issues": [],
                "ci_cd_workflows": [],
                "helper_workflows": [],
                "ci_cd_present": False,
            }

        workflows: List[Dict] = []
        issues: List[Dict] = []
        ci_cd_workflows: List[str] = []
        helper_workflows: List[str] = []

        for workflow_file in sorted(workflow_dir.glob("*.y*ml")):
            content = self._safe_read_text(workflow_file)
            rel_file = self._relative(workflow_file)
            is_agent_workflow = "ai-devops-agent" in workflow_file.name
            is_ci_cd_workflow = self._looks_like_ci_cd_workflow(workflow_file, content) and not is_agent_workflow
            workflow = {
                "file": rel_file,
                "uses_checkout": "actions/checkout@" in content,
                "uses_setup_python": "actions/setup-python@" in content,
                "uses_setup_node": "actions/setup-node@" in content,
                "runs_tests": bool(re.search(r"\b(pytest|npm test|pnpm test|yarn test|mvn test|go test)\b", content)),
                "uploads_artifacts": "actions/upload-artifact@" in content,
                "create_pull_request": "create-pull-request@" in content,
                "is_agent_workflow": is_agent_workflow,
                "is_ci_cd_workflow": is_ci_cd_workflow,
            }
            workflows.append(workflow)
            if is_agent_workflow:
                helper_workflows.append(rel_file)
            if is_ci_cd_workflow:
                ci_cd_workflows.append(rel_file)

            if is_agent_workflow:
                if "--apply-fixes" in content:
                    issues.append({
                        "severity": "HIGH",
                        "file": rel_file,
                        "issue": "Workflow calls unsupported --apply-fixes flag.",
                        "fix": "Run the agent only with --mode ai.",
                    })
                if "suggestions.md" in content and "SUGGESTIONS.md" not in content:
                    issues.append({
                        "severity": "MEDIUM",
                        "file": rel_file,
                        "issue": "Workflow expects suggestions.md but the agent now writes AI_DEVOPS_REPORT.md.",
                        "fix": "Update artifact and PR comment steps to use AI_DEVOPS_REPORT.md.",
                    })
                if "generate-pipeline" in content or "suggest-changes" in content or "generate-and-commit" in content or "analyze-only" in content:
                    issues.append({
                        "severity": "MEDIUM",
                        "file": rel_file,
                        "issue": "Workflow references legacy execution modes.",
                        "fix": "Replace legacy execution modes with the single supported ai mode.",
                    })

            if is_ci_cd_workflow and not workflow["runs_tests"]:
                issues.append({
                    "severity": "MEDIUM",
                    "file": rel_file,
                    "issue": "Workflow does not appear to run application tests.",
                    "fix": "Add test commands for the detected frontend/backend stack.",
                })

        if not ci_cd_workflows:
            issues.append({
                "severity": "MEDIUM",
                "file": ".github/workflows",
                "issue": "No CI/CD implementation workflow is present; the AI DevOps Agent workflow is not counted as CI/CD.",
                "fix": "Add an application CI/CD workflow for build, test, and deployment stages.",
            })

        return {
            "exists": True,
            "workflows": workflows,
            "issues": issues,
            "ci_cd_workflows": ci_cd_workflows,
            "helper_workflows": helper_workflows,
            "ci_cd_present": bool(ci_cd_workflows),
        }

    def _analyze_security(self, frontend: Dict, backend: Dict, infrastructure: Dict) -> Dict:
        issues = {"frontend": [], "backend": [], "infrastructure": [], "github_actions": []}

        if frontend.get("exists"):
            issues["frontend"].extend(self._check_frontend_security(self.project_root / frontend["path"]))
        if backend.get("exists"):
            issues["backend"].extend(self._check_backend_security(self.project_root / backend["path"], backend["language"]))
        issues["infrastructure"].extend(self._check_infrastructure_security(infrastructure))
        issues["github_actions"].extend(self._check_workflow_security())
        return issues

    def _check_frontend_security(self, frontend_path: Path) -> List[Dict]:
        issues: List[Dict] = []
        for file in frontend_path.rglob("*"):
            if self._is_ignored(file) or not file.is_file() or file.suffix not in {".js", ".jsx", ".ts", ".tsx"}:
                continue
            content = self._safe_read_text(file)
            if "eval(" in content:
                issues.append({
                    "severity": "HIGH",
                    "file": self._relative(file),
                    "issue": "eval() usage detected.",
                    "fix": "Replace eval() with safer parsing or direct function calls.",
                })
            if ".innerHTML" in content:
                issues.append({
                    "severity": "MEDIUM",
                    "file": self._relative(file),
                    "issue": "innerHTML usage may introduce XSS risk.",
                    "fix": "Prefer textContent or sanitize content before inserting HTML.",
                })

        package_file = frontend_path / "package.json"
        if package_file.exists():
            lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
            if not any((frontend_path / name).exists() for name in lockfiles):
                issues.append({
                    "severity": "MEDIUM",
                    "file": self._relative(package_file),
                    "issue": "Frontend package manager lockfile is missing.",
                    "fix": "Commit the appropriate lockfile for reproducible installs.",
                })
        return issues

    def _check_backend_security(self, backend_path: Path, language: str) -> List[Dict]:
        issues: List[Dict] = []

        if language == "python":
            for file in backend_path.rglob("*.py"):
                if self._is_ignored(file):
                    continue
                content = self._safe_read_text(file)
                if "pickle.load" in content:
                    issues.append({
                        "severity": "HIGH",
                        "file": self._relative(file),
                        "issue": "Unsafe pickle deserialization detected.",
                        "fix": "Use a safer serialization format such as JSON.",
                    })
                if re.search(r"execute\s*\([^)]*[%+]", content):
                    issues.append({
                        "severity": "HIGH",
                        "file": self._relative(file),
                        "issue": "Potential SQL injection via dynamic query construction.",
                        "fix": "Use parameterized queries or ORM query builders.",
                    })
                if re.search(r"(password|api_key|secret|token)\s*=\s*[\"']", content, re.IGNORECASE):
                    issues.append({
                        "severity": "HIGH",
                        "file": self._relative(file),
                        "issue": "Possible hard-coded secret detected.",
                        "fix": "Move secrets to environment variables or a secret manager.",
                    })
        elif language in {"javascript", "typescript"}:
            for file in list(backend_path.rglob("*.js")) + list(backend_path.rglob("*.ts")):
                if self._is_ignored(file):
                    continue
                content = self._safe_read_text(file)
                if re.search(r"(password|api[_-]?key|secret|token)\s*[:=]\s*[\"']", content, re.IGNORECASE):
                    issues.append({
                        "severity": "HIGH",
                        "file": self._relative(file),
                        "issue": "Possible hard-coded secret detected.",
                        "fix": "Move secrets to environment variables or a secret manager.",
                    })
        return issues

    def _check_infrastructure_security(self, infrastructure: Dict) -> List[Dict]:
        issues: List[Dict] = []

        for dockerfile in self.project_root.rglob("Dockerfile"):
            if self._is_ignored(dockerfile):
                continue
            content = self._safe_read_text(dockerfile)
            if re.search(r"FROM\s+\S+:latest", content):
                issues.append({
                    "severity": "MEDIUM",
                    "file": self._relative(dockerfile),
                    "issue": 'Dockerfile uses "latest" image tag.',
                    "fix": "Pin base images to specific versions for reproducibility.",
                })

        for tf_file in infrastructure.get("terraform_files", []):
            path = self.project_root / tf_file
            content = self._safe_read_text(path)
            if 'cidr_blocks = ["0.0.0.0/0"]' in content and "from_port   = 22" in content:
                issues.append({
                    "severity": "HIGH",
                    "file": tf_file,
                    "issue": "Terraform exposes SSH to the public internet.",
                    "fix": "Restrict SSH ingress to known IP ranges or a bastion host.",
                })
            if 'cidr_blocks = ["0.0.0.0/0"]' in content and "from_port   = 5432" in content:
                issues.append({
                    "severity": "HIGH",
                    "file": tf_file,
                    "issue": "Terraform exposes database access publicly.",
                    "fix": "Restrict database ingress to private networks or specific security groups.",
                })
        return issues

    def _check_workflow_security(self) -> List[Dict]:
        issues: List[Dict] = []
        for workflow_file in (self.project_root / ".github" / "workflows").glob("*.y*ml"):
            content = self._safe_read_text(workflow_file)
            if "pull_request_target" in content:
                issues.append({
                    "severity": "HIGH",
                    "file": self._relative(workflow_file),
                    "issue": "pull_request_target can expose repository secrets to untrusted changes.",
                    "fix": "Use pull_request unless pull_request_target is strictly required and hardened.",
                })
            if re.search(r"permissions:\s*\n\s*contents:\s*write", content) and "pull_request" in content:
                issues.append({
                    "severity": "MEDIUM",
                    "file": self._relative(workflow_file),
                    "issue": "Workflow grants write permissions; review whether that scope is necessary.",
                    "fix": "Reduce permissions to least privilege where possible.",
                })
        return issues

    def _analyze_best_practices(
        self,
        repository: Dict,
        frontend: Dict,
        backend: Dict,
        infrastructure: Dict,
        docker: Dict,
        github_actions: Dict,
    ) -> Dict:
        strengths: List[str] = []
        gaps: List[str] = []
        suggestions: List[str] = []

        if frontend.get("exists"):
            strengths.append(
                f"Frontend detected at {frontend['path']} using {frontend['language']} / {frontend['framework']}."
            )
            if frontend.get("template_count"):
                strengths.append(
                    f"Frontend includes {frontend['template_count']} HTML template files, indicating server-rendered UI coverage."
                )
        if backend.get("exists"):
            strengths.append(
                f"Backend detected at {backend['path']} using {backend['language']} / {backend['framework']}."
            )
            if backend.get("tests"):
                strengths.append(
                    f"Backend test assets detected: {backend['tests'].get('count', 0)} file(s)."
                )
            if backend.get("datastores"):
                strengths.append(
                    f"Backend datastore signals detected: {', '.join(backend['datastores'])}."
                )
        if infrastructure.get("terraform_exists"):
            strengths.append("Repository already contains Terraform configuration.")
        if github_actions.get("helper_workflows"):
            strengths.append("Repository contains GitHub Actions helper or analysis workflows.")
        if github_actions.get("ci_cd_present"):
            strengths.append("Repository already contains CI/CD workflows for the application.")
        if infrastructure.get("compose_services"):
            strengths.append(
                f"Docker Compose services detected: {', '.join(infrastructure['compose_services'])}."
            )

        if frontend.get("exists") and backend.get("exists") and not docker.get("compose_exists"):
            gaps.append("Frontend and backend were detected, but docker-compose is missing.")
            suggestions.append("Add docker-compose.yml to make local multi-service validation easier.")
        if backend.get("exists") and not infrastructure.get("terraform_exists") and not infrastructure.get("kubernetes_files"):
            gaps.append("Backend exists but no deployable IaC was found.")
            suggestions.append("Add Terraform, Helm, or Kubernetes manifests for repeatable environment provisioning.")
            if backend.get("framework") == "spring-boot":
                suggestions.append("Generate IaC for a Java web app plus its database dependencies, not only the application host.")
        if github_actions.get("exists") and github_actions.get("issues"):
            gaps.append("Existing GitHub Actions workflows contain drift against current agent capabilities.")
            suggestions.append("Align workflow inputs, filenames, and supported CLI modes with the current agent.")
        if github_actions.get("exists") and not github_actions.get("ci_cd_present"):
            gaps.append("No application CI/CD implementation workflow was detected.")
            suggestions.append("Add a separate CI/CD workflow for build, test, and deployment; do not rely on the agent workflow as the app pipeline.")
        if backend.get("exists") and backend.get("language") == "python":
            backend_path = self.project_root / backend["path"]
            if not any((backend_path / name).exists() for name in ("requirements.txt", "pyproject.toml")):
                gaps.append("Python backend exists without a clear dependency manifest.")
                suggestions.append("Add requirements.txt or pyproject.toml for deterministic installs.")
        if backend.get("language") == "java" and not backend.get("tests", {}).get("count"):
            gaps.append("Java backend detected without obvious test sources.")
            suggestions.append("Add Maven or Gradle test execution and ensure test sources are committed.")
        if frontend.get("framework") == "server-rendered-html":
            suggestions.append("Treat embedded templates and static assets as the frontend surface when assessing coverage and delivery needs.")

        if not strengths:
            suggestions.append(
                "Repository structure is unconventional; consider defining clearer app directories or pipeline_request.txt metadata."
            )

        suggestions.extend(infrastructure.get("suggestions", []))

        return {
            "strengths": strengths,
            "gaps": gaps,
            "suggestions": suggestions,
            "repo_languages": repository.get("top_languages", {}),
        }

    def _detect_js_framework(self, package_data: Dict) -> str:
        deps = self._combined_dependencies(package_data)
        if "next" in deps:
            return "nextjs"
        if "react" in deps:
            return "react"
        if "vue" in deps:
            return "vue"
        if "@angular/core" in deps:
            return "angular"
        if "svelte" in deps:
            return "svelte"
        return "generic-nodejs"

    def _detect_node_backend_framework(self, package_data: Dict) -> str:
        deps = self._combined_dependencies(package_data)
        if "@nestjs/core" in deps:
            return "nestjs"
        if "express" in deps:
            return "express"
        if "koa" in deps:
            return "koa"
        if "fastify" in deps:
            return "fastify"
        return "generic-node-backend"

    def _detect_python_framework(self, backend_path: Path) -> str:
        for py_file in backend_path.rglob("*.py"):
            if self._is_ignored(py_file):
                continue
            content = self._safe_read_text(py_file).lower()
            if re.search(r"(^|\n)\s*(from\s+fastapi\s+import|import\s+fastapi\b)", content):
                return "fastapi"
            if re.search(r"(^|\n)\s*(from\s+flask\s+import|import\s+flask\b)", content):
                return "flask"
            if re.search(r"(^|\n)\s*(from\s+django\s+import|import\s+django\b)", content):
                return "django"
            if re.search(r"(^|\n)\s*(from\s+aiohttp\s+import|import\s+aiohttp\b)", content):
                return "aiohttp"
        return "generic-python"

    def _looks_like_python_service(self, backend_path: Path) -> bool:
        signals = (
            "uvicorn.run(",
            "fastapi(",
            "flask(",
            "django.core",
            "app = fastapi",
            "app = flask",
            "router = apirouter",
        )
        for py_file in backend_path.rglob("*.py"):
            if self._is_ignored(py_file):
                continue
            content = self._safe_read_text(py_file, 12000).lower()
            if any(signal in content for signal in signals):
                return True
            if re.search(r"if __name__ == [\"']__main__[\"']", content):
                return True
        return False

    def _detect_java_framework(self, backend_path: Path) -> str:
        for file in backend_path.rglob("*"):
            if self._is_ignored(file) or not file.is_file():
                continue
            content = self._safe_read_text(file, 12000).lower()
            if "spring-boot" in content or "springframework.boot" in content:
                return "spring-boot"
        return "generic-java"

    def _detect_runtime(self, backend_path: Path, language: str) -> Dict:
        runtime: Dict[str, str] = {}
        if language == "java":
            if (backend_path / "pom.xml").exists():
                runtime["build_tool"] = "maven"
            elif (backend_path / "build.gradle").exists() or (backend_path / "build.gradle.kts").exists():
                runtime["build_tool"] = "gradle"
            runtime["java_version"] = self._extract_java_version(backend_path)
        elif language == "python":
            runtime["build_tool"] = "pip"
        elif language in {"javascript", "typescript"}:
            runtime["build_tool"] = "npm"
        return runtime

    def _extract_java_version(self, backend_path: Path) -> str:
        pom = backend_path / "pom.xml"
        if pom.exists():
            content = self._safe_read_text(pom)
            match = re.search(r"<java\.version>([^<]+)</java\.version>", content)
            if match:
                return match.group(1).strip()
        gradle = backend_path / "build.gradle"
        if gradle.exists():
            content = self._safe_read_text(gradle)
            match = re.search(r"JavaLanguageVersion\.of\((\d+)\)", content)
            if match:
                return match.group(1)
        return "unknown"

    def _extract_xml_artifact_ids(self, path: Path) -> List[str]:
        content = self._safe_read_text(path)
        return re.findall(r"<artifactId>([^<]+)</artifactId>", content)[:25]

    def _extract_gradle_dependencies(self, path: Path) -> List[str]:
        content = self._safe_read_text(path)
        return re.findall(r"['\"]([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[^'\"]+)['\"]", content)[:25]

    def _discover_tests(self, backend_path: Path, language: str) -> Dict:
        test_files: List[Path] = []
        patterns = {
            "java": ["*Test.java", "*Tests.java"],
            "python": ["test_*.py", "*_test.py"],
            "javascript": ["*.test.js", "*.spec.js"],
            "typescript": ["*.test.ts", "*.spec.ts"],
            "go": ["*_test.go"],
        }
        for pattern in patterns.get(language, []):
            test_files.extend(path for path in backend_path.rglob(pattern) if not self._is_ignored(path))
        return {
            "count": len(test_files),
            "examples": [self._relative(path) for path in sorted(test_files)[:8]],
        }

    def _detect_datastores(self, backend_path: Path) -> List[str]:
        markers = {
            "h2": ("h2",),
            "mysql": ("mysql", "mysql-connector"),
            "postgres": ("postgres", "postgresql"),
            "mariadb": ("mariadb",),
        }
        found: List[str] = []
        for file in backend_path.rglob("*"):
            if self._is_ignored(file) or not file.is_file():
                continue
            if file.suffix.lower() not in TEXT_FILE_EXTENSIONS and file.name not in {"pom.xml", "build.gradle", "build.gradle.kts"}:
                continue
            content = self._safe_read_text(file, 12000).lower()
            for name, tokens in markers.items():
                if name not in found and any(token in content for token in tokens):
                    found.append(name)
        return found

    def _find_backend_entrypoints(self, backend_path: Path, language: str) -> List[str]:
        entrypoints: List[str] = []
        if language == "java":
            for file in backend_path.rglob("*.java"):
                if self._is_ignored(file):
                    continue
                rel = self._relative(file)
                if "/src/test/" in f"/{rel}":
                    continue
                content = self._safe_read_text(file, 12000)
                if "@SpringBootApplication" in content or "public static void main" in content:
                    entrypoints.append(rel)
        elif language == "python":
            for file in backend_path.rglob("*.py"):
                if self._is_ignored(file):
                    continue
                content = self._safe_read_text(file, 12000)
                if re.search(r"if __name__ == [\"']__main__[\"']", content):
                    entrypoints.append(self._relative(file))
        return entrypoints[:8]

    def _collect_frontend_evidence(self, frontend_path: Path, frontend_kind: str, package_data: Dict) -> List[str]:
        evidence: List[str] = []
        if frontend_kind == "spring-static":
            templates_dir = self.project_root / "src" / "main" / "resources" / "templates"
            static_dir = self.project_root / "src" / "main" / "resources" / "static"
            if templates_dir.exists():
                evidence.append(f"Spring templates found in `{self._relative(templates_dir)}`.")
            if static_dir.exists():
                evidence.append(f"Static assets found in `{self._relative(static_dir)}`.")
        if package_data.get("scripts"):
            evidence.append("package.json scripts indicate a buildable frontend application.")
        return evidence

    def _parse_compose_services(self) -> List[str]:
        services: List[str] = []
        for rel_path in [
            self._relative(path)
            for path in self.project_root.rglob("docker-compose*.yml")
            if not self._is_ignored(path)
        ] + [
            self._relative(path)
            for path in self.project_root.rglob("docker-compose*.yaml")
            if not self._is_ignored(path)
        ]:
            path = self.project_root / rel_path
            content = self._safe_read_text(path)
            if yaml is not None:
                try:
                    parsed = yaml.safe_load(content) or {}
                    if isinstance(parsed, dict):
                        for name in (parsed.get("services") or {}).keys():
                            if name not in services:
                                services.append(str(name))
                        continue
                except Exception:
                    pass
            for match in re.finditer(r"^\s{2}([A-Za-z0-9_.-]+):\s*$", content, re.MULTILINE):
                name = match.group(1)
                if name != "services" and name not in services:
                    services.append(name)
        return services

    def _looks_like_ci_cd_workflow(self, workflow_file: Path, content: str) -> bool:
        filename = workflow_file.name.lower()
        if "ai-devops-agent" in filename:
            return False
        ci_cd_name_markers = ("ci", "cd", "deploy", "release", "build", "pipeline", "test")
        ci_cd_step_markers = (
            "docker build",
            "terraform ",
            "kubectl ",
            "helm ",
            "npm test",
            "pytest",
            "mvn test",
            "gradlew test",
            "go test",
        )
        if any(marker in filename for marker in ci_cd_name_markers):
            return True
        return any(marker in content.lower() for marker in ci_cd_step_markers)

    def _detect_go_framework(self, backend_path: Path) -> str:
        for file in backend_path.rglob("*.go"):
            if self._is_ignored(file):
                continue
            content = self._safe_read_text(file, 12000).lower()
            if "gin-gonic/gin" in content:
                return "gin"
            if "fiber" in content:
                return "fiber"
        return "generic-go"

    def _detect_port(self, path: Path, default: int) -> int:
        patterns = [
            r"(?:port|PORT)\s*[:=]\s*[\"']?(\d{2,5})",
            r"listen\s*\(\s*[\"']?(\d{2,5})",
            r"uvicorn\.run\([^)]*port\s*=\s*(\d{2,5})",
            r"EXPOSE\s+(\d{2,5})",
        ]
        for file in path.rglob("*"):
            if self._is_ignored(file) or not file.is_file():
                continue
            if file.suffix.lower() not in PORT_SCAN_EXTENSIONS and file.name != "Dockerfile":
                continue
            content = self._safe_read_text(file, 20000)
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return int(match.group(1))
        return default

    def _find_yaml_with_markers(self, markers: Sequence[str]) -> Iterable[Path]:
        for path in list(self.project_root.rglob("*.yml")) + list(self.project_root.rglob("*.yaml")):
            if self._is_ignored(path):
                continue
            content = self._safe_read_text(path, 10000)
            if all(marker in content for marker in markers):
                yield path

    def _combined_dependencies(self, package_data: Dict) -> Dict:
        return {
            **package_data.get("dependencies", {}),
            **package_data.get("devDependencies", {}),
        }

    def _has_typescript_sources(self, path: Path) -> bool:
        return any(
            file.suffix in {".ts", ".tsx"}
            for file in path.rglob("*")
            if not self._is_ignored(file) and file.is_file()
        )

    def _load_json(self, path: Path) -> Dict:
        try:
            return json.loads(self._safe_read_text(path) or "{}")
        except json.JSONDecodeError:
            return {}

    def _read_requirements(self, path: Path) -> List[str]:
        return [
            line.strip()
            for line in self._safe_read_text(path).splitlines()
            if line.strip() and not line.strip().startswith("#")
        ][:25]

    def _is_ignored(self, path: Path) -> bool:
        return any(part in IGNORED_DIRS for part in path.parts)


class OpenAIEnricher:
    """Uses the OpenAI API to turn static analysis into richer DevOps guidance."""

    def __init__(self, token: str, model: str = "gpt-5.4-mini"):
        self.token = token
        self.model = model
        self.endpoint = "https://api.openai.com/v1/chat/completions"

    def enrich(self, analysis: Dict) -> Dict:
        prompt = self._build_prompt(analysis)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior DevOps architect. "
                        "Review the repository analysis and return only valid JSON. "
                        "Focus on architecture, CI/CD, IaC, security, operational maturity, "
                        "and concrete next steps."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "response_format": {"type": "json_object"},
        }

        response = requests.post(
            self.endpoint,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=120,
        )
        response.raise_for_status()
        data = response.json()

        text = ""
        choices = data.get("choices", [])
        if choices:
            text = choices[0].get("message", {}).get("content", "") or ""
        if not text:
            raise ValueError("OpenAI response did not include any content")

        try:
            result = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("OpenAI response was not valid JSON") from exc

        result["model"] = self.model
        return result

    def _build_prompt(self, analysis: Dict) -> str:
        compact = {
            "repository": analysis.get("repository", {}),
            "frontend": analysis.get("frontend", {}),
            "backend": analysis.get("backend", {}),
            "infrastructure": analysis.get("infrastructure", {}),
            "docker": analysis.get("docker", {}),
            "github_actions": analysis.get("github_actions", {}),
            "security": analysis.get("security", {}),
            "best_practices": analysis.get("best_practices", {}),
        }
        return (
            "Analyze this repository scan and return JSON with the following keys:\n"
            "executive_summary: string\n"
            "architecture_summary: string\n"
            "frontend_assessment: string\n"
            "backend_assessment: string\n"
            "iac_recommendations: array of strings\n"
            "workflow_review: array of strings\n"
            "security_priorities: array of strings\n"
            "quick_wins: array of strings\n"
            "long_term_improvements: array of strings\n"
            "generated_asset_guidance: object with keys terraform, workflow, docker_compose, readme and string values\n"
            "Keep recommendations concrete and based only on the supplied scan.\n\n"
            f"Repository scan:\n{json.dumps(compact, indent=2)}"
        )


class PipelineGenerator:
    """Generates CI/CD pipeline files and infrastructure code."""

    def __init__(self, project_root: str, config_file: str = "pipeline_request.txt", openai_token: Optional[str] = None):
        self.project_root = Path(project_root).resolve()
        self.config_file = self.project_root / config_file
        self.analyzer = ProjectAnalyzer(str(self.project_root), openai_token)
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        if not self.config_file.exists():
            return self._default_config()

        config: Dict[str, str] = {}
        try:
            for line in self.config_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                raw = line.strip()
                if raw and ":" in raw and not raw.startswith("#"):
                    key, value = raw.split(":", 1)
                    config[key.strip()] = value.strip()
        except Exception as exc:
            print(f"Warning: could not load config: {exc}")

        return config or self._default_config()

    def _default_config(self) -> Dict:
        return {
            "pipeline_name": "devops-pipeline",
            "environment": "production",
            "target": "aws_ec2",
            "instance_type": "t3.micro",
            "frontend_port": "3000",
            "backend_port": "8000",
        }

    def generate(self, analysis: Optional[Dict] = None, ai_insights: Optional[Dict] = None) -> bool:
        print("Generating pipeline components...")
        analysis = analysis or self.analyzer.analyze()
        self._generate_github_workflow(analysis)
        if analysis["frontend"].get("exists") or analysis["backend"].get("exists"):
            self._generate_docker_compose(analysis)
        self._generate_terraform(analysis)
        self._generate_readme(analysis, ai_insights or {})
        print("Pipeline generation complete")
        return True

    def _generate_github_workflow(self, analysis: Dict) -> None:
        workflow_dir = self.project_root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)

        frontend = analysis["frontend"]
        backend = analysis["backend"]
        target = self.config.get("target", "aws_ec2")
        frontend_setup = ""
        backend_setup = ""
        frontend_steps = ""
        backend_steps = ""

        if frontend.get("exists"):
            if frontend.get("type") != "spring-static":
                frontend_setup = """      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
"""
                frontend_path = frontend["path"]
                frontend_install = self._frontend_install_command(frontend)
                frontend_test = self._frontend_test_command(frontend)
                frontend_build = self._frontend_build_command(frontend)
                frontend_steps = f"""      - name: Install frontend dependencies
        working-directory: {frontend_path}
        run: {frontend_install}

      - name: Test frontend
        working-directory: {frontend_path}
        run: {frontend_test}

      - name: Build frontend
        working-directory: {frontend_path}
        run: {frontend_build}
"""
            else:
                frontend_steps = """      - name: Validate server-rendered frontend assets
        run: |
          test -d src/main/resources/templates
          test -d src/main/resources/static || true
"""

        if backend.get("exists") and backend.get("language") == "python":
            backend_setup = """      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
"""
            backend_path = backend["path"]
            backend_steps = f"""      - name: Install backend dependencies
        working-directory: {backend_path}
        run: |
          python -m pip install --upgrade pip
          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi

      - name: Test backend
        working-directory: {backend_path}
        run: |
          pytest --tb=short || python -m unittest discover
"""
        elif backend.get("exists") and backend.get("language") in {"javascript", "typescript"}:
            if not frontend_setup:
                frontend_setup = """      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
"""
            backend_path = backend["path"]
            backend_steps = f"""      - name: Install backend dependencies
        working-directory: {backend_path}
        run: npm install

      - name: Test backend
        working-directory: {backend_path}
        run: npm test --if-present
"""
        elif backend.get("exists") and backend.get("language") == "java":
            backend_setup = """      - name: Set up Java
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'
"""
            build_command = "./mvnw test" if (self.project_root / "mvnw").exists() else "./gradlew test"
            backend_steps = f"""      - name: Test backend
        working-directory: {backend['path']}
        run: |
          chmod +x mvnw gradlew 2>/dev/null || true
          {build_command}
"""

        docker_step = ""
        if (self.project_root / "Dockerfile").exists():
            docker_step = """      - name: Build Docker image
        run: docker build -t app:latest .
"""

        deploy_env = ""
        deploy_setup = ""
        deploy_steps = f"""      - name: Skip cloud deployment
        run: echo "Cloud target {target} requires environment-specific setup; skipping automated deploy."
"""
        if target == "aws_ec2":
            deploy_env = """    env:
      CLOUD_DEPLOY_ENABLED: ${{ secrets.AWS_ACCESS_KEY_ID != '' && secrets.AWS_SECRET_ACCESS_KEY != '' && vars.AWS_REGION != '' }}
"""
            deploy_setup = """      - name: Configure AWS credentials
        if: env.CLOUD_DEPLOY_ENABLED == 'true'
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ vars.AWS_REGION }}

      - name: Set up Terraform
        if: env.CLOUD_DEPLOY_ENABLED == 'true'
        uses: hashicorp/setup-terraform@v3
"""
            deploy_steps = """      - name: Terraform apply
        if: env.CLOUD_DEPLOY_ENABLED == 'true'
        working-directory: terraform
        run: |
          terraform init
          terraform validate
          terraform plan -out=tfplan
          terraform apply -auto-approve tfplan

      - name: Skip cloud deployment
        if: env.CLOUD_DEPLOY_ENABLED != 'true'
        run: echo "AWS credentials or AWS region are not configured; skipping Terraform apply."
"""

        workflow = f"""name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
{frontend_setup}{backend_setup}{frontend_steps}{backend_steps}{docker_step}      - name: Repository summary
        run: |
          echo "Frontend: {frontend.get('framework', 'not detected')}"
          echo "Backend: {backend.get('framework', 'not detected')}"

  deploy:
    if: github.ref == 'refs/heads/main'
    needs: validate
    runs-on: ubuntu-latest
{deploy_env}    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

{deploy_setup}{deploy_steps}
"""
        workflow_file = workflow_dir / "pipeline.yml"
        workflow_file.write_text(workflow, encoding="utf-8")
        print(f"Generated: {self._relative(workflow_file)}")

    def _frontend_install_command(self, frontend: Dict) -> str:
        deps = set(frontend.get("dependencies", []))
        if "pnpm" in deps:
            return "pnpm install --frozen-lockfile"
        return "npm ci || npm install"

    def _frontend_test_command(self, frontend: Dict) -> str:
        scripts = frontend.get("scripts", {})
        if "test" in scripts:
            return "npm test --if-present"
        return "echo 'No frontend test script found'"

    def _frontend_build_command(self, frontend: Dict) -> str:
        scripts = frontend.get("scripts", {})
        if "build" in scripts:
            return "npm run build"
        return "echo 'No frontend build script found'"

    def _generate_docker_compose(self, analysis: Dict) -> None:
        frontend = analysis["frontend"]
        backend = analysis["backend"]
        datastores = backend.get("datastores", [])
        compose: Dict[str, object] = {
            "version": "3.9",
            "services": {},
            "volumes": {},
        }

        if frontend.get("exists") and frontend.get("type") != "spring-static":
            compose["services"]["frontend"] = {
                "build": f"./{frontend['path']}",
                "ports": [f"{frontend.get('port', 3000)}:3000"],
                "environment": {"NODE_ENV": "production"},
                "restart": "unless-stopped",
            }

        if backend.get("exists"):
            internal_port = backend.get("port", 8080 if backend.get("language") == "java" else 8000)
            preferred_datastore = self.config.get("database_engine", "").strip().lower()
            if preferred_datastore not in datastores:
                preferred_datastore = datastores[0] if datastores else ""
            backend_service: Dict[str, object] = {
                "build": f"./{backend['path']}",
                "ports": [f"{internal_port}:{internal_port}"],
                "environment": {
                    "APP_ENV": "production",
                    "DEBUG": "false",
                },
                "restart": "unless-stopped",
                "healthcheck": {
                    "test": ["CMD-SHELL", f"curl -fsS http://localhost:{internal_port}/ || exit 1"],
                    "interval": "30s",
                    "timeout": "10s",
                    "retries": 5,
                    "start_period": "30s",
                },
            }
            depends_on: Dict[str, Dict[str, str]] = {}
            if "mysql" in datastores:
                depends_on["mysql"] = {"condition": "service_healthy"}
            if "postgres" in datastores:
                depends_on["postgres"] = {"condition": "service_healthy"}
            if preferred_datastore == "mysql":
                backend_service["environment"]["DB_HOST"] = "mysql"
                backend_service["environment"]["DB_PORT"] = "3306"
            elif preferred_datastore == "postgres":
                backend_service["environment"]["DB_HOST"] = "postgres"
                backend_service["environment"]["DB_PORT"] = "5432"
            if depends_on:
                backend_service["depends_on"] = depends_on
            compose["services"]["backend"] = backend_service

        if "mysql" in datastores:
            compose["services"]["mysql"] = {
                "image": "mysql:8.4",
                "restart": "unless-stopped",
                "ports": ["3306:3306"],
                "environment": {
                    "MYSQL_DATABASE": "appdb",
                    "MYSQL_USER": "appuser",
                    "MYSQL_PASSWORD": "change-me",
                    "MYSQL_ROOT_PASSWORD": "change-me-root",
                },
                "volumes": [
                    "mysql_data:/var/lib/mysql",
                    "./docker/init/mysql:/docker-entrypoint-initdb.d:ro",
                ],
                "healthcheck": {
                    "test": ["CMD-SHELL", "mysqladmin ping -h localhost -p$$MYSQL_ROOT_PASSWORD"],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 10,
                },
            }
            compose["volumes"]["mysql_data"] = {}

        if "postgres" in datastores:
            compose["services"]["postgres"] = {
                "image": "postgres:16",
                "restart": "unless-stopped",
                "ports": ["5432:5432"],
                "environment": {
                    "POSTGRES_DB": "appdb",
                    "POSTGRES_USER": "appuser",
                    "POSTGRES_PASSWORD": "change-me",
                },
                "volumes": [
                    "postgres_data:/var/lib/postgresql/data",
                    "./docker/init/postgres:/docker-entrypoint-initdb.d:ro",
                ],
                "healthcheck": {
                    "test": ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER -d $$POSTGRES_DB"],
                    "interval": "10s",
                    "timeout": "5s",
                    "retries": 10,
                },
            }
            compose["volumes"]["postgres_data"] = {}

        self._generate_container_init_scripts(datastores)
        compose_file = self.project_root / "docker-compose.yml"
        if yaml is not None:
            compose_file.write_text(
                yaml.dump(compose, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
        else:
            compose_file.write_text(self._dump_simple_yaml(compose), encoding="utf-8")
        print(f"Generated: {self._relative(compose_file)}")

    def _generate_container_init_scripts(self, datastores: Sequence[str]) -> None:
        docker_dir = self.project_root / "docker" / "init"
        if "mysql" in datastores:
            mysql_dir = docker_dir / "mysql"
            mysql_dir.mkdir(parents=True, exist_ok=True)
            (mysql_dir / "01-init.sql").write_text(
                "CREATE DATABASE IF NOT EXISTS appdb;\n"
                "CREATE USER IF NOT EXISTS 'appuser'@'%' IDENTIFIED BY 'change-me';\n"
                "GRANT ALL PRIVILEGES ON appdb.* TO 'appuser'@'%';\n"
                "FLUSH PRIVILEGES;\n",
                encoding="utf-8",
            )
        if "postgres" in datastores:
            postgres_dir = docker_dir / "postgres"
            postgres_dir.mkdir(parents=True, exist_ok=True)
            (postgres_dir / "01-init.sql").write_text(
                "CREATE USER appuser WITH PASSWORD 'change-me';\n"
                "CREATE DATABASE appdb OWNER appuser;\n",
                encoding="utf-8",
            )

    def _dump_simple_yaml(self, value: object, indent: int = 0) -> str:
        prefix = " " * indent
        if isinstance(value, dict):
            lines: List[str] = []
            for key, item in value.items():
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}{key}:")
                    lines.append(self._dump_simple_yaml(item, indent + 2))
                else:
                    lines.append(f"{prefix}{key}: {self._yaml_scalar(item)}")
            return "\n".join(lines) + ("\n" if indent == 0 else "")
        if isinstance(value, list):
            lines = []
            for item in value:
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}-")
                    lines.append(self._dump_simple_yaml(item, indent + 2))
                else:
                    lines.append(f"{prefix}- {self._yaml_scalar(item)}")
            return "\n".join(lines)
        return f"{prefix}{self._yaml_scalar(value)}"

    def _yaml_scalar(self, value: object) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "null"
        if isinstance(value, (int, float)):
            return str(value)
        text = str(value)
        if text == "" or any(ch in text for ch in [":", "{", "}", "[", "]", "#", "&", "*", "?", "|", ">", "%", "@", ",", "$"]) or text.strip() != text:
            return json.dumps(text)
        return text

    def _generate_terraform(self, analysis: Dict) -> None:
        frontend = analysis["frontend"]
        backend = analysis["backend"]
        tf_dir = self.project_root / "terraform"
        tf_dir.mkdir(parents=True, exist_ok=True)
        app_port = backend.get("port", frontend.get("port", 8080))

        ingress_blocks = [
            """  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }""",
            """  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }""",
        ]
        if frontend.get("exists") and frontend.get("type") != "spring-static":
            ingress_blocks.append(
                f"""  ingress {{
    from_port   = {frontend.get('port', 3000)}
    to_port     = {frontend.get('port', 3000)}
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}"""
            )
        if backend.get("exists"):
            ingress_blocks.append(
                f"""  ingress {{
    from_port   = {app_port}
    to_port     = {app_port}
    protocol    = "tcp"
    cidr_blocks = [var.application_ingress_cidr]
  }}"""
            )

        resource_name = self.config.get("pipeline_name", "devops-pipeline").replace("-", "_")
        main_tf = f"""terraform {{
  required_version = ">= 1.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = var.aws_region
}}

locals {{
  app_name = "{self.config.get('pipeline_name', 'devops-pipeline')}"
}}

data "aws_ami" "ubuntu" {{
  most_recent = true
  owners      = ["099720109477"]

  filter {{
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }}
}}

resource "aws_security_group" "app" {{
  name = "${{local.app_name}}-sg"

{os.linesep.join(ingress_blocks)}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

resource "aws_instance" "{resource_name}" {{
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.app.id]
  user_data              = templatefile("${{path.module}}/user_data.sh", {{
    app_name = local.app_name
    app_port = var.app_port
  }})

  tags = {{
    Name        = "${{local.app_name}}-instance"
    Environment = var.environment
  }}
}}
"""
        variables_tf = f"""variable "aws_region" {{
  type    = string
  default = "us-east-1"
}}

variable "instance_type" {{
  type    = string
  default = "t3.micro"
}}

variable "environment" {{
  type    = string
  default = "production"
}}

variable "app_port" {{
  type    = number
  default = {app_port}
}}

variable "application_ingress_cidr" {{
  type    = string
  default = "10.0.0.0/16"
}}
"""
        outputs_tf = f"""output "instance_ip" {{
  value       = aws_instance.{resource_name}.public_ip
  description = "Public IP of the application host"
}}

output "instance_id" {{
  value       = aws_instance.{resource_name}.id
  description = "EC2 instance id"
}}

output "security_group_id" {{
  value       = aws_security_group.app.id
  description = "Security group attached to the application host"
}}
"""
        tfvars_example = f"""aws_region = "us-east-1"
instance_type = "{self.config.get('instance_type', 't3.micro')}"
environment = "{self.config.get('environment', 'production')}"
app_port = {app_port}
application_ingress_cidr = "10.0.0.0/16"
"""
        user_data = """#!/bin/bash
set -euxo pipefail

apt-get update
apt-get install -y docker.io docker-compose-plugin
systemctl enable docker
systemctl start docker

mkdir -p /opt/${app_name}
cat >/etc/motd <<EOM
${app_name} bootstrap complete.
Application port: ${app_port}
Deploy your compose bundle or container image into /opt/${app_name}.
EOM
"""
        (tf_dir / "main.tf").write_text(main_tf, encoding="utf-8")
        (tf_dir / "variables.tf").write_text(variables_tf, encoding="utf-8")
        (tf_dir / "outputs.tf").write_text(outputs_tf, encoding="utf-8")
        (tf_dir / "terraform.tfvars.example").write_text(tfvars_example, encoding="utf-8")
        (tf_dir / "user_data.sh").write_text(user_data, encoding="utf-8")
        print(f"Generated: {self._relative(tf_dir)}")

    def _generate_readme(self, analysis: Dict, ai_insights: Dict) -> None:
        repo = analysis["repository"]
        frontend = analysis["frontend"]
        backend = analysis["backend"]
        infrastructure = analysis["infrastructure"]
        workflows = analysis["github_actions"]
        best_practices = analysis["best_practices"]

        readme = f"""# {self.config.get('pipeline_name', 'Application')}

Generated by AI DevOps Agent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Repository Overview

- Files scanned: {repo.get('file_count', 0)}
- Top languages: {self._format_kv(repo.get('top_languages', {}))}
- Important manifests: {', '.join(repo.get('important_files', [])[:8]) or 'None detected'}

## Application Detection

- Frontend: {self._describe_component(frontend)}
- Backend: {self._describe_component(backend)}

## Infrastructure Review

- Terraform files: {len(infrastructure.get('terraform_files', []))}
- Kubernetes manifests: {len(infrastructure.get('kubernetes_files', []))}
- Helm charts: {len(infrastructure.get('helm_charts', []))}
- GitHub Actions workflows: {len(workflows.get('workflows', []))}

## Best-Practice Alignment

{self._format_markdown_list(best_practices.get('strengths', []), fallback='- No notable strengths were auto-detected.')}

### Gaps

{self._format_markdown_list(best_practices.get('gaps', []), fallback='- No major gaps were auto-detected.')}

### Suggestions

{self._format_markdown_list(best_practices.get('suggestions', []), fallback='- No additional suggestions at this time.')}

## Security Findings

{self._format_security_findings(analysis['security'])}

## AI Guidance

- Executive summary: {ai_insights.get('executive_summary', 'No AI summary generated.')}
- Architecture: {ai_insights.get('architecture_summary', 'No AI architecture summary generated.')}

### AI Quick Wins

{self._format_markdown_list(ai_insights.get('quick_wins', []), fallback='- No AI quick wins generated.')}
"""

        readme_file = self.project_root / "README_GENERATED.md"
        readme_file.write_text(readme, encoding="utf-8")
        print(f"Generated: {self._relative(readme_file)}")

    def _format_security_findings(self, security: Dict) -> str:
        all_issues = (
            security.get("frontend", [])
            + security.get("backend", [])
            + security.get("infrastructure", [])
            + security.get("github_actions", [])
        )
        if not all_issues:
            return "- No major security issues were auto-detected."
        lines = []
        for issue in all_issues[:8]:
            lines.append(
                f"- [{issue.get('severity', '?')}] {issue.get('issue', 'Unknown issue')} "
                f"({issue.get('file', 'N/A')})"
            )
        return "\n".join(lines)

    def _describe_component(self, component: Dict) -> str:
        if not component.get("exists"):
            return "Not detected"
        return (
            f"{component.get('language', 'unknown')} / {component.get('framework', 'unknown')} "
            f"at `{component.get('path', '.')}` on port {component.get('port', 'N/A')}"
        )

    def _format_markdown_list(self, items: Sequence[str], fallback: str) -> str:
        if not items:
            return fallback
        return "\n".join(f"- {item}" for item in items)

    def _format_kv(self, mapping: Dict) -> str:
        if not mapping:
            return "None"
        return ", ".join(f"{key}: {value}" for key, value in mapping.items())

    def _relative(self, path: Path) -> str:
        return str(path.relative_to(self.project_root))


class AIDevOpsAgent:
    """Single AI mode runner for analysis, enrichment, and generation."""

    def __init__(
        self,
        project_root: str,
        config_file: str,
        openai_token: str,
        openai_model: str = "gpt-5.4-mini",
    ):
        self.project_root = Path(project_root).resolve()
        self.config_file = config_file
        self.analyzer = ProjectAnalyzer(str(self.project_root), openai_token)
        self.generator = PipelineGenerator(str(self.project_root), config_file, openai_token)
        self.enricher = OpenAIEnricher(openai_token, openai_model)

    def run(self) -> bool:
        analysis = self.analyzer.analyze()
        ai_insights = self.enricher.enrich(analysis)
        self._print_analysis(analysis, ai_insights)
        self.generator.generate(analysis, ai_insights)
        report = self._create_ai_report(analysis, ai_insights)
        report_file = self.project_root / "AI_DEVOPS_REPORT.md"
        report_file.write_text(report, encoding="utf-8")
        print(f"AI report written to: {report_file.relative_to(self.project_root)}")
        return True

    def _create_ai_report(self, analysis: Dict, ai_insights: Dict) -> str:
        frontend = analysis["frontend"]
        backend = analysis["backend"]
        infrastructure = analysis["infrastructure"]
        workflows = analysis["github_actions"]
        best_practices = analysis["best_practices"]
        docker = analysis["docker"]
        repo = analysis["repository"]

        return f"""# AI DevOps Agent Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
OpenAI model: `{ai_insights.get('model', 'unknown')}`

## Executive Summary

{ai_insights.get('executive_summary', 'No AI summary generated.')}

## Repository Summary

- Files scanned: {repo.get('file_count', 0)}
- Top languages: {self._format_mapping(repo.get('top_languages', {}))}
- Important manifests: {', '.join(repo.get('important_files', [])[:12]) or 'None detected'}

## Architecture

- AI architecture summary: {ai_insights.get('architecture_summary', 'No AI architecture summary generated.')}
- Frontend: {ai_insights.get('frontend_assessment', 'No AI frontend assessment generated.')}
- Backend: {ai_insights.get('backend_assessment', 'No AI backend assessment generated.')}

## Frontend Detection

{self._format_component_status(frontend)}

### Frontend Evidence
{self._format_simple_list(frontend.get('evidence', []), 'No direct frontend evidence captured.')}

### Frontend Assets
{self._format_simple_list(frontend.get('template_examples', []), 'No template examples captured.')}
{self._format_labeled_list('Static asset examples', frontend.get('static_asset_examples', []))}

## Backend Detection

{self._format_component_status(backend)}

### Backend Runtime
{self._format_mapping_lines(backend.get('runtime', {}), 'No runtime metadata captured.')}

### Backend Entry Points
{self._format_simple_list(backend.get('entrypoints', []), 'No entrypoints captured.')}

### Backend Tests
{self._format_test_summary(backend.get('tests', {}))}

### Backend Dependencies
{self._format_simple_list(backend.get('dependencies', [])[:12], 'No dependency summary captured.')}

### Datastore Signals
{self._format_simple_list(backend.get('datastores', []), 'No datastore signals detected.')}

## IaC Review

- Terraform: {'Yes' if infrastructure.get('terraform_exists') else 'No'}
- Kubernetes manifests: {len(infrastructure.get('kubernetes_files', []))}
- Helm charts: {len(infrastructure.get('helm_charts', []))}
- Docker Compose: {'Yes' if docker.get('compose_exists') else 'No'}
- Compose services: {', '.join(infrastructure.get('compose_services', [])) or 'None detected'}
- SQL/bootstrap assets: {len(infrastructure.get('db_init_files', []))}

### Heuristic IaC Recommendations
{self._format_iac_recommendations(frontend, backend, infrastructure)}

### AI IaC Recommendations
{self._format_simple_list(ai_insights.get('iac_recommendations', []), 'No AI IaC recommendations generated.')}

## Workflow Review

- Workflows found: {len(workflows.get('workflows', []))}
- CI/CD workflows found: {len(workflows.get('ci_cd_workflows', []))}
- Helper workflows found: {len(workflows.get('helper_workflows', []))}
{self._format_issue_lines(workflows.get('issues', []), 'No workflow issues auto-detected.')}

### AI Workflow Review
{self._format_simple_list(ai_insights.get('workflow_review', []), 'No AI workflow review generated.')}

## Security Priorities

{self._format_security_recommendations(analysis['security'])}

### AI Security Priorities
{self._format_simple_list(ai_insights.get('security_priorities', []), 'No AI security priorities generated.')}

## Best-Practice Alignment

### Strengths
{self._format_simple_list(best_practices.get('strengths', []), 'None auto-detected.')}

### Gaps
{self._format_simple_list(best_practices.get('gaps', []), 'No major gaps auto-detected.')}

### Heuristic Actions
{self._format_simple_list(best_practices.get('suggestions', []), 'No additional heuristic actions suggested.')}

### AI Quick Wins
{self._format_simple_list(ai_insights.get('quick_wins', []), 'No AI quick wins generated.')}

### AI Long-Term Improvements
{self._format_simple_list(ai_insights.get('long_term_improvements', []), 'No AI long-term improvements generated.')}

## Generated Asset Guidance

{self._format_mapping_lines(ai_insights.get('generated_asset_guidance', {}), 'No AI asset guidance generated.')}
"""

    def _format_component_status(self, component: Dict) -> str:
        if not component.get("exists"):
            return "- Not detected"
        lines = [
            "- Detected",
            f"- Path: `{component.get('path', '.')}`",
            f"- Language: {component.get('language', 'unknown')}",
            f"- Framework: {component.get('framework', 'unknown')}",
            f"- Port: {component.get('port', 'N/A')}",
        ]
        if component.get("type"):
            lines.append(f"- Type: {component.get('type')}")
        if component.get("build_files"):
            lines.append(f"- Build files: {', '.join(component.get('build_files', []))}")
        if component.get("template_count"):
            lines.append(f"- HTML templates: {component.get('template_count')}")
        return "\n".join(lines)

    def _format_security_recommendations(self, security: Dict) -> str:
        all_issues = (
            security.get("frontend", [])
            + security.get("backend", [])
            + security.get("infrastructure", [])
            + security.get("github_actions", [])
        )
        if not all_issues:
            return "- No major security issues detected."
        return "\n".join(
            f"- [{issue.get('severity', '?')}] {issue.get('issue', 'Unknown')} "
            f"({issue.get('file', 'N/A')})"
            for issue in all_issues[:10]
        )

    def _format_issue_lines(self, issues: Sequence[Dict], fallback: str) -> str:
        if not issues:
            return f"- {fallback}"
        return "\n".join(
            f"- [{issue.get('severity', '?')}] {issue.get('issue', 'Unknown')} ({issue.get('file', 'N/A')})"
            for issue in issues
        )

    def _format_simple_list(self, items: Sequence[str], fallback: str) -> str:
        if not items:
            return f"- {fallback}"
        return "\n".join(f"- {item}" for item in items)

    def _format_labeled_list(self, label: str, items: Sequence[str]) -> str:
        if not items:
            return f"\n### {label}\n- None captured"
        return f"\n### {label}\n" + "\n".join(f"- {item}" for item in items)

    def _format_mapping(self, mapping: Dict) -> str:
        if not mapping:
            return "None"
        return ", ".join(f"{key}: {value}" for key, value in mapping.items())

    def _format_mapping_lines(self, mapping: Dict, fallback: str) -> str:
        if not mapping:
            return f"- {fallback}"
        return "\n".join(f"- {key}: {value}" for key, value in mapping.items())

    def _format_test_summary(self, tests: Dict) -> str:
        if not tests:
            return "- No test metadata captured."
        count = tests.get("count", 0)
        examples = tests.get("examples", [])
        lines = [f"- Test files detected: {count}"]
        if examples:
            lines.extend(f"- {example}" for example in examples)
        return "\n".join(lines)

    def _format_iac_recommendations(self, frontend: Dict, backend: Dict, infrastructure: Dict) -> str:
        recommendations: List[str] = []
        if backend.get("framework") == "spring-boot":
            port = backend.get("port", 8080)
            recommendations.append(
                f"Provision a Java application host that exposes port {port} and runs the Spring Boot service."
            )
        if frontend.get("framework") == "server-rendered-html":
            recommendations.append(
                "Treat the HTML templates and static assets as part of the deployed application package rather than a separate Node build."
            )
        for service in infrastructure.get("compose_services", []):
            if service in {"mysql", "postgres", "postgresql"}:
                recommendations.append(
                    f"Add managed or self-hosted database infrastructure for the `{service}` service currently described in Docker Compose."
                )
        if not recommendations:
            recommendations.append("No additional IaC recommendations generated.")
        return "\n".join(f"- {item}" for item in recommendations)

    def _print_analysis(self, analysis: Dict, ai_insights: Dict) -> None:
        print("=" * 60)
        print("AI DEVOPS ANALYSIS RESULTS")
        print("=" * 60)

        repo = analysis["repository"]
        print(f"\nFiles scanned: {repo.get('file_count', 0)}")
        print(f"Top languages: {self._format_mapping(repo.get('top_languages', {}))}")
        print(f"\nFrontend:\n{self._format_component_status(analysis['frontend'])}")
        if analysis["frontend"].get("evidence"):
            print("Frontend evidence:")
            for item in analysis["frontend"]["evidence"][:5]:
                print(f"- {item}")
        print(f"\nBackend:\n{self._format_component_status(analysis['backend'])}")
        if analysis["backend"].get("tests"):
            print(f"Backend tests: {analysis['backend']['tests'].get('count', 0)} file(s)")
        if analysis["backend"].get("datastores"):
            print(f"Backend datastores: {', '.join(analysis['backend']['datastores'])}")
        print("\nInfrastructure:")
        print(f"- Terraform: {analysis['infrastructure'].get('terraform_exists')}")
        print(f"- Kubernetes manifests: {len(analysis['infrastructure'].get('kubernetes_files', []))}")
        print(f"- Docker Compose services: {', '.join(analysis['infrastructure'].get('compose_services', [])) or 'none'}")
        print(f"- GitHub Actions workflows: {len(analysis['github_actions'].get('workflows', []))}")
        print(f"- CI/CD workflows: {len(analysis['github_actions'].get('ci_cd_workflows', []))}")
        print(f"- Helper workflows: {len(analysis['github_actions'].get('helper_workflows', []))}")
        print(f"\nAI model: {ai_insights.get('model', 'unknown')}")
        print(f"AI summary: {ai_insights.get('executive_summary', 'No AI summary generated.')}")

        all_issues = (
            analysis["security"].get("frontend", [])
            + analysis["security"].get("backend", [])
            + analysis["security"].get("infrastructure", [])
            + analysis["security"].get("github_actions", [])
        )
        print("\nSecurity Summary:")
        if all_issues:
            high = len([issue for issue in all_issues if issue.get("severity") == "HIGH"])
            medium = len([issue for issue in all_issues if issue.get("severity") == "MEDIUM"])
            print(f"- HIGH: {high}")
            print(f"- MEDIUM: {medium}")
        else:
            print("- No issues detected")

        workflow_issues = analysis["github_actions"].get("issues", [])
        if workflow_issues:
            print("\nWorkflow Issues:")
            for issue in workflow_issues:
                print(f"- [{issue.get('severity', '?')}] {issue.get('issue')} ({issue.get('file')})")

        print("\n" + "=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="AI DevOps Agent")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--config-file", default="pipeline_request.txt", help="Config file")
    parser.add_argument("--openai-token", help="OpenAI API token")
    parser.add_argument("--openai-model", default="gpt-5.4-mini", help="OpenAI model for AI analysis")
    parser.add_argument(
        "--mode",
        choices=["ai"],
        default="ai",
        help="Execution mode",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("AI DevOps Agent")
    print("=" * 50)

    try:
        openai_token = args.openai_token or os.getenv("OPENAI_API_TOKEN")
        if not openai_token:
            raise ValueError("OPENAI_API_TOKEN or --openai-token is required for ai mode")

        agent = AIDevOpsAgent(
            args.project_root,
            args.config_file,
            openai_token,
            args.openai_model,
        )

        success = agent.run()
        if success:
            print("\nWorkflow completed successfully")
            sys.exit(0)

        print("\nWorkflow failed")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled by user")
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
