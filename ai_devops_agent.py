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

        if not candidates:
            return {"exists": False}

        best = max(candidates, key=lambda item: (item.score, -len(item.path.parts)))
        package_file = best.path / "package.json"
        package_data = self._load_json(package_file) if package_file.exists() else {}

        return {
            "exists": True,
            "path": self._relative(best.path),
            "type": best.kind,
            "language": best.language,
            "framework": best.framework,
            "port": self._detect_port(best.path, 3000),
            "scripts": package_data.get("scripts", {}),
            "dependencies": sorted(self._combined_dependencies(package_data).keys())[:25],
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

        return {
            "exists": True,
            "path": self._relative(best.path),
            "type": best.kind,
            "language": best.language,
            "framework": best.framework,
            "port": self._detect_port(best.path, 8000),
            "dependencies": dependencies,
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

        suggestions: List[str] = []
        if backend.get("exists") and not terraform_files and not kubernetes_files and not helm_charts:
            suggestions.append("Backend detected but no Terraform, Kubernetes, or Helm configuration was found.")
        if frontend.get("exists") and backend.get("exists") and not (self.project_root / "docker-compose.yml").exists():
            suggestions.append("Full-stack app detected without docker-compose.yml for local orchestration.")

        return {
            "terraform_exists": bool(terraform_files),
            "terraform_files": terraform_files,
            "kubernetes_files": kubernetes_files,
            "helm_charts": sorted(set(helm_charts)),
            "ansible_files": ansible_files,
            "cloudformation_files": cloudformation_files,
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
            return {"exists": False, "workflows": [], "issues": []}

        workflows: List[Dict] = []
        issues: List[Dict] = []

        for workflow_file in sorted(workflow_dir.glob("*.y*ml")):
            content = self._safe_read_text(workflow_file)
            workflow = {
                "file": self._relative(workflow_file),
                "uses_checkout": "actions/checkout@" in content,
                "uses_setup_python": "actions/setup-python@" in content,
                "uses_setup_node": "actions/setup-node@" in content,
                "runs_tests": bool(re.search(r"\b(pytest|npm test|pnpm test|yarn test|mvn test|go test)\b", content)),
                "uploads_artifacts": "actions/upload-artifact@" in content,
                "create_pull_request": "create-pull-request@" in content,
            }
            workflows.append(workflow)

            if "ai-devops-agent" in workflow_file.name:
                if "--apply-fixes" in content:
                    issues.append({
                        "severity": "HIGH",
                        "file": self._relative(workflow_file),
                        "issue": "Workflow calls unsupported --apply-fixes flag.",
                        "fix": "Use supported modes only: analyze-only, generate, generate-and-commit, suggest-changes.",
                    })
                if "suggestions.md" in content and "SUGGESTIONS.md" not in content:
                    issues.append({
                        "severity": "MEDIUM",
                        "file": self._relative(workflow_file),
                        "issue": "Workflow expects suggestions.md but the agent writes SUGGESTIONS.md.",
                        "fix": "Update artifact and PR comment steps to use SUGGESTIONS.md.",
                    })
                if "generate-pipeline" in content:
                    issues.append({
                        "severity": "MEDIUM",
                        "file": self._relative(workflow_file),
                        "issue": "Workflow dispatch mode uses generate-pipeline instead of the supported generate mode.",
                        "fix": "Replace generate-pipeline with generate.",
                    })

            if not workflow["runs_tests"]:
                issues.append({
                    "severity": "MEDIUM",
                    "file": self._relative(workflow_file),
                    "issue": "Workflow does not appear to run application tests.",
                    "fix": "Add test commands for the detected frontend/backend stack.",
                })

        return {"exists": True, "workflows": workflows, "issues": issues}

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
        if backend.get("exists"):
            strengths.append(
                f"Backend detected at {backend['path']} using {backend['language']} / {backend['framework']}."
            )
        if infrastructure.get("terraform_exists"):
            strengths.append("Repository already contains Terraform configuration.")
        if github_actions.get("exists"):
            strengths.append("Repository already contains GitHub Actions workflows.")

        if frontend.get("exists") and backend.get("exists") and not docker.get("compose_exists"):
            gaps.append("Frontend and backend were detected, but docker-compose is missing.")
            suggestions.append("Add docker-compose.yml to make local multi-service validation easier.")
        if backend.get("exists") and not infrastructure.get("terraform_exists") and not infrastructure.get("kubernetes_files"):
            gaps.append("Backend exists but no deployable IaC was found.")
            suggestions.append("Add Terraform, Helm, or Kubernetes manifests for repeatable environment provisioning.")
        if github_actions.get("exists") and github_actions.get("issues"):
            gaps.append("Existing GitHub Actions workflows contain drift against current agent capabilities.")
            suggestions.append("Align workflow inputs, filenames, and supported CLI modes with the current agent.")
        if backend.get("exists") and backend.get("language") == "python":
            backend_path = self.project_root / backend["path"]
            if not any((backend_path / name).exists() for name in ("requirements.txt", "pyproject.toml")):
                gaps.append("Python backend exists without a clear dependency manifest.")
                suggestions.append("Add requirements.txt or pyproject.toml for deterministic installs.")

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

    def generate(self) -> bool:
        print("Generating pipeline components...")
        analysis = self.analyzer.analyze()
        self._generate_github_workflow(analysis)
        if analysis["frontend"].get("exists") or analysis["backend"].get("exists"):
            self._generate_docker_compose(analysis)
        self._generate_terraform(analysis)
        self._generate_readme(analysis)
        print("Pipeline generation complete")
        return True

    def _generate_github_workflow(self, analysis: Dict) -> None:
        workflow_dir = self.project_root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)

        frontend = analysis["frontend"]
        backend = analysis["backend"]
        frontend_setup = ""
        backend_setup = ""
        frontend_steps = ""
        backend_steps = ""

        if frontend.get("exists"):
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

        docker_step = ""
        if (self.project_root / "Dockerfile").exists():
            docker_step = """      - name: Build Docker image
        run: docker build -t app:latest .
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
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Deployment placeholder
        run: echo "Deploy to {self.config.get('target', 'aws_ec2')} here"
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
        lines = ["version: '3.9'", "services:"]

        if frontend.get("exists"):
            lines.extend([
                "  frontend:",
                f"    build: ./{frontend['path']}",
                "    ports:",
                f"      - '{frontend.get('port', 3000)}:3000'",
                "    environment:",
                "      NODE_ENV: production",
            ])

        if backend.get("exists"):
            lines.extend([
                "  backend:",
                f"    build: ./{backend['path']}",
                "    ports:",
                f"      - '{backend.get('port', 8000)}:8000'",
                "    environment:",
                "      APP_ENV: production",
                "      DEBUG: 'false'",
            ])

        compose_file = self.project_root / "docker-compose.yml"
        compose_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Generated: {self._relative(compose_file)}")

    def _generate_terraform(self, analysis: Dict) -> None:
        frontend = analysis["frontend"]
        backend = analysis["backend"]
        tf_dir = self.project_root / "terraform"
        tf_dir.mkdir(parents=True, exist_ok=True)

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
        if frontend.get("exists"):
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
    from_port   = {backend.get('port', 8000)}
    to_port     = {backend.get('port', 8000)}
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
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

data "aws_ami" "ubuntu" {{
  most_recent = true
  owners      = ["099720109477"]

  filter {{
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }}
}}

resource "aws_security_group" "app" {{
  name = "{self.config.get('pipeline_name', 'devops-pipeline')}-sg"

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

  tags = {{
    Name        = "{self.config.get('pipeline_name', 'devops-pipeline')}-instance"
    Environment = var.environment
  }}
}}

output "instance_ip" {{
  value       = aws_instance.{resource_name}.public_ip
  description = "Public IP of the application host"
}}
"""
        variables_tf = """variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "environment" {
  type    = string
  default = "production"
}
"""
        (tf_dir / "main.tf").write_text(main_tf, encoding="utf-8")
        (tf_dir / "variables.tf").write_text(variables_tf, encoding="utf-8")
        print(f"Generated: {self._relative(tf_dir)}")

    def _generate_readme(self, analysis: Dict) -> None:
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


class WorkflowOrchestrator:
    """Orchestrates execution modes and report output."""

    def __init__(self, project_root: str, config_file: str, openai_token: Optional[str] = None):
        self.project_root = Path(project_root).resolve()
        self.config_file = config_file
        self.analyzer = ProjectAnalyzer(str(self.project_root), openai_token)
        self.generator = PipelineGenerator(str(self.project_root), config_file, openai_token)

    def run(self, mode: str) -> bool:
        if mode == "analyze-only":
            return self.analyze_only()
        if mode == "generate":
            return self.generator.generate()
        if mode == "generate-and-commit":
            return self.generate_and_commit()
        if mode == "suggest-changes":
            return self.suggest_changes()
        print(f"Unknown mode: {mode}")
        return False

    def analyze_only(self) -> bool:
        analysis = self.analyzer.analyze()
        self._print_analysis(analysis)
        return True

    def generate_and_commit(self) -> bool:
        if not self.generator.generate():
            return False
        try:
            subprocess.run(["git", "add", "."], cwd=self.project_root, check=True)
            subprocess.run(
                ["git", "commit", "-m", "AI: Generated CI/CD pipeline"],
                cwd=self.project_root,
                check=True,
            )
            print("Changes committed")
        except subprocess.CalledProcessError as exc:
            print(f"Git commit failed: {exc}")
        return True

    def suggest_changes(self) -> bool:
        analysis = self.analyzer.analyze()
        suggestions = self._create_suggestions(analysis)
        output_file = self.project_root / "SUGGESTIONS.md"
        output_file.write_text(suggestions, encoding="utf-8")
        print(f"Suggestions written to: {output_file.relative_to(self.project_root)}")
        return True

    def _create_suggestions(self, analysis: Dict) -> str:
        frontend = analysis["frontend"]
        backend = analysis["backend"]
        infrastructure = analysis["infrastructure"]
        workflows = analysis["github_actions"]
        best_practices = analysis["best_practices"]

        return f"""# AI DevOps Agent - Suggestions

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Repository Summary

- Files scanned: {analysis['repository'].get('file_count', 0)}
- Top languages: {self._format_mapping(analysis['repository'].get('top_languages', {}))}

## Frontend

{self._format_component_status(frontend)}

## Backend

{self._format_component_status(backend)}

## IaC Review

- Terraform: {'Yes' if infrastructure.get('terraform_exists') else 'No'}
- Kubernetes manifests: {len(infrastructure.get('kubernetes_files', []))}
- Helm charts: {len(infrastructure.get('helm_charts', []))}
- Docker Compose: {'Yes' if analysis['docker'].get('compose_exists') else 'No'}

## GitHub Actions Review

- Workflows found: {len(workflows.get('workflows', []))}
{self._format_issue_lines(workflows.get('issues', []), 'No workflow issues auto-detected.')}

## Security Recommendations

{self._format_security_recommendations(analysis['security'])}

## Best-Practice Suggestions

### Strengths
{self._format_simple_list(best_practices.get('strengths', []), 'None auto-detected.')}

### Gaps
{self._format_simple_list(best_practices.get('gaps', []), 'No major gaps auto-detected.')}

### Recommended Actions
{self._format_simple_list(best_practices.get('suggestions', []), 'No additional actions suggested.')}
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

    def _format_mapping(self, mapping: Dict) -> str:
        if not mapping:
            return "None"
        return ", ".join(f"{key}: {value}" for key, value in mapping.items())

    def _print_analysis(self, analysis: Dict) -> None:
        print("=" * 60)
        print("PROJECT ANALYSIS RESULTS")
        print("=" * 60)

        repo = analysis["repository"]
        print(f"\nFiles scanned: {repo.get('file_count', 0)}")
        print(f"Top languages: {self._format_mapping(repo.get('top_languages', {}))}")
        print(f"\nFrontend:\n{self._format_component_status(analysis['frontend'])}")
        print(f"\nBackend:\n{self._format_component_status(analysis['backend'])}")
        print("\nInfrastructure:")
        print(f"- Terraform: {analysis['infrastructure'].get('terraform_exists')}")
        print(f"- Kubernetes manifests: {len(analysis['infrastructure'].get('kubernetes_files', []))}")
        print(f"- GitHub Actions workflows: {len(analysis['github_actions'].get('workflows', []))}")

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
    parser.add_argument(
        "--mode",
        choices=["analyze-only", "generate", "generate-and-commit", "suggest-changes"],
        default="generate",
        help="Execution mode",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    parser.add_argument("--analyze-only", action="store_true", help="Only analyze the project")
    parser.add_argument("--auto-commit", action="store_true", help="Automatically commit changes")
    parser.add_argument("--suggest-changes", action="store_true", help="Suggest changes instead of generating")

    args = parser.parse_args()

    print("AI DevOps Agent")
    print("=" * 50)

    try:
        openai_token = args.openai_token or os.getenv("OPENAI_API_TOKEN")
        orchestrator = WorkflowOrchestrator(args.project_root, args.config_file, openai_token)

        if args.analyze_only:
            mode = "analyze-only"
        elif args.suggest_changes:
            mode = "suggest-changes"
        elif args.auto_commit:
            mode = "generate-and-commit"
        else:
            mode = args.mode

        success = orchestrator.run(mode)
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
