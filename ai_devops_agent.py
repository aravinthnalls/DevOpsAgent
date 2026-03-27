#!/usr/bin/env python3
"""
Simplified AI-Powered DevOps Agent
===================================

A straightforward DevOps automation tool that:
- Analyzes project structure and security
- Generates CI/CD pipelines
- Orchestrates workflow execution modes
- Generates infrastructure templates

All workflow logic is in Python for simplicity.
"""

import os
import sys
import json
import yaml
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import argparse
import requests


class ProjectAnalyzer:
    """Analyzes project structure, dependencies, and security."""
    
    def __init__(self, project_root: str, openai_token: Optional[str] = None):
        self.project_root = Path(project_root)
        self.openai_token = openai_token
        self.results = {}
    
    def analyze(self) -> Dict:
        """Run complete project analysis."""
        print("📊 Analyzing project...")
        
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'project_root': str(self.project_root),
            'frontend': self._analyze_frontend(),
            'backend': self._analyze_backend(),
            'infrastructure': self._analyze_infrastructure(),
            'docker': self._analyze_docker(),
            'git': self._analyze_git(),
            'security': self._analyze_security(),
        }
        
        return self.results
    
    def _analyze_frontend(self) -> Dict:
        """Detect frontend framework and configuration."""
        frontend_path = self.project_root / 'frontend'
        
        if not frontend_path.exists():
            return {'exists': False}
        
        result = {'exists': True, 'path': str(frontend_path)}
        
        # Check for Node.js/npm
        if (frontend_path / 'package.json').exists():
            try:
                pkg_data = json.loads((frontend_path / 'package.json').read_text())
                result['type'] = 'nodejs'
                result['framework'] = self._detect_js_framework(pkg_data)
                result['scripts'] = pkg_data.get('scripts', {})
                result['port'] = self._detect_port(frontend_path, 3000)
            except Exception as e:
                print(f"⚠️  Could not parse package.json: {e}")
        elif (frontend_path / 'index.html').exists():
            result['type'] = 'static'
            result['framework'] = 'html-css-js'
            result['port'] = 3000
        
        return result
    
    def _analyze_backend(self) -> Dict:
        """Detect backend framework and configuration."""
        backend_path = self.project_root / 'backend'
        
        if not backend_path.exists():
            return {'exists': False}
        
        result = {'exists': True, 'path': str(backend_path)}
        
        # Check for Python backend
        if (backend_path / 'requirements.txt').exists() or any(backend_path.glob('*.py')):
            result['language'] = 'python'
            result['framework'] = self._detect_python_framework(backend_path)
            result['port'] = self._detect_port(backend_path, 8000)
            
            # Read dependencies
            req_file = backend_path / 'requirements.txt'
            if req_file.exists():
                result['dependencies'] = [
                    line.strip() for line in req_file.read_text().split('\n')
                    if line.strip() and not line.startswith('#')
                ]
        
        return result
    
    def _detect_js_framework(self, package_data: Dict) -> str:
        """Detect JavaScript framework from package.json."""
        deps = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
        
        if 'react' in deps:
            return 'react'
        elif 'vue' in deps:
            return 'vue'
        elif 'angular' in deps:
            return 'angular'
        elif 'next' in deps:
            return 'nextjs'
        elif 'svelte' in deps:
            return 'svelte'
        else:
            return 'generic-nodejs'
    
    def _detect_python_framework(self, backend_path: Path) -> str:
        """Detect Python framework from files."""
        for py_file in backend_path.glob('*.py'):
            content = py_file.read_text()
            if 'fastapi' in content:
                return 'fastapi'
            elif 'flask' in content:
                return 'flask'
            elif 'django' in content:
                return 'django'
        return 'generic-python'
    
    def _detect_port(self, path: Path, default: int) -> int:
        """Detect port from source files."""
        for file in path.rglob('*'):
            if file.is_file() and file.suffix in ['.py', '.js', '.ts']:
                try:
                    content = file.read_text()
                    match = re.search(r'(?:port|PORT)\s*[:=]\s*(\d{4,5})', content)
                    if match:
                        return int(match.group(1))
                except:
                    pass
        return default
    
    def _analyze_infrastructure(self) -> Dict:
        """Check for existing infrastructure as code."""
        terraform_path = self.project_root / 'terraform'
        
        return {
            'terraform_exists': terraform_path.exists(),
            'terraform_files': [f.name for f in terraform_path.glob('*.tf')] if terraform_path.exists() else []
        }
    
    def _analyze_docker(self) -> Dict:
        """Check Docker configuration."""
        return {
            'dockerfiles': [str(f.relative_to(self.project_root)) for f in self.project_root.rglob('Dockerfile')],
            'compose_exists': (self.project_root / 'docker-compose.yml').exists()
        }
    
    def _analyze_git(self) -> Dict:
        """Check git repository."""
        git_dir = self.project_root / '.git'
        
        if not git_dir.exists():
            return {'is_repo': False}
        
        result = {'is_repo': True}
        
        try:
            current_branch = subprocess.run(
                ['git', 'branch', '--show-current'],
                cwd=self.project_root,
                capture_output=True,
                text=True
            ).stdout.strip()
            result['branch'] = current_branch
        except:
            pass
        
        return result
    
    def _analyze_security(self) -> Dict:
        """Identify security issues."""
        issues = {'frontend': [], 'backend': [], 'infrastructure': []}
        
        # Frontend security checks
        frontend_path = self.project_root / 'frontend'
        if frontend_path.exists():
            issues['frontend'].extend(self._check_frontend_security(frontend_path))
        
        # Backend security checks
        backend_path = self.project_root / 'backend'
        if backend_path.exists():
            issues['backend'].extend(self._check_backend_security(backend_path))
        
        # Infrastructure security
        issues['infrastructure'].extend(self._check_infrastructure_security())
        
        return issues
    
    def _check_frontend_security(self, frontend_path: Path) -> List[Dict]:
        """Check frontend security."""
        issues = []
        
        # Check for eval() in JS files
        for js_file in frontend_path.rglob('*.js'):
            content = js_file.read_text()
            if 'eval(' in content:
                issues.append({
                    'severity': 'HIGH',
                    'file': js_file.name,
                    'issue': 'eval() usage detected',
                    'fix': 'Remove eval() - use safer alternatives like JSON.parse()'
                })
            if '.innerHTML' in content and 'userInput' in content:
                issues.append({
                    'severity': 'MEDIUM',
                    'file': js_file.name,
                    'issue': 'innerHTML with user input (XSS risk)',
                    'fix': 'Use textContent or DOMPurify for sanitization'
                })
        
        # Check for package-lock.json
        if not (frontend_path / 'package-lock.json').exists() and (frontend_path / 'package.json').exists():
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Missing package-lock.json',
                'fix': 'Run npm install to generate lock file'
            })
        
        return issues
    
    def _check_backend_security(self, backend_path: Path) -> List[Dict]:
        """Check backend security."""
        issues = []
        
        # Check for common vulnerabilities in Python
        for py_file in backend_path.rglob('*.py'):
            content = py_file.read_text()
            
            if 'pickle.load' in content:
                issues.append({
                    'severity': 'HIGH',
                    'file': py_file.name,
                    'issue': 'Unsafe pickle deserialization',
                    'fix': 'Use JSON instead of pickle'
                })
            
            if re.search(r'execute\s*\([^)]*\+', content):
                issues.append({
                    'severity': 'HIGH',
                    'file': py_file.name,
                    'issue': 'SQL injection risk (string concatenation)',
                    'fix': 'Use parameterized queries'
                })
            
            if re.search(r'(password|api_key|secret)\s*=\s*["\']', content):
                issues.append({
                    'severity': 'HIGH',
                    'file': py_file.name,
                    'issue': 'Hard-coded credentials',
                    'fix': 'Move to environment variables'
                })
        
        return issues
    
    def _check_infrastructure_security(self) -> List[Dict]:
        """Check infrastructure security."""
        issues = []
        
        # Check Dockerfiles
        for dockerfile in self.project_root.rglob('Dockerfile'):
            content = dockerfile.read_text()
            if 'FROM' not in content or 'latest' in content:
                issues.append({
                    'severity': 'MEDIUM',
                    'file': dockerfile.name,
                    'issue': 'Using "latest" base image tag',
                    'fix': 'Pin specific version for reproducibility'
                })
        
        return issues


class PipelineGenerator:
    """Generates CI/CD pipeline files and infrastructure code."""
    
    def __init__(self, project_root: str, config_file: str = 'pipeline_request.txt', openai_token: Optional[str] = None):
        self.project_root = Path(project_root)
        self.config_file = self.project_root / config_file
        self.analyzer = ProjectAnalyzer(project_root, openai_token)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load pipeline configuration."""
        if not self.config_file.exists():
            return self._default_config()
        
        config = {}
        try:
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        config[key.strip()] = value.strip()
        except Exception as e:
            print(f"⚠️  Could not load config: {e}")
        
        return config or self._default_config()
    
    def _default_config(self) -> Dict:
        """Return default configuration."""
        return {
            'pipeline_name': 'devops-pipeline',
            'environment': 'production',
            'target': 'aws_ec2',
            'instance_type': 't3.micro',
            'frontend_port': '3000',
            'backend_port': '8000'
        }
    
    def generate(self) -> bool:
        """Generate all pipeline components."""
        print("\n🚀 Generating pipeline components...")
        
        analysis = self.analyzer.analyze()
        
        # Generate GitHub Actions workflow
        self._generate_github_workflow(analysis)
        
        # Generate Docker files if needed
        if analysis['docker']['dockerfiles'] or analysis['frontend']['exists'] or analysis['backend']['exists']:
            self._generate_docker_compose(analysis)
        
        # Generate Terraform infrastructure
        self._generate_terraform(analysis)
        
        # Generate README
        self._generate_readme(analysis)
        
        print("\n✅ Pipeline generation complete!")
        return True
    
    def _generate_github_workflow(self, analysis: Dict) -> None:
        """Generate GitHub Actions workflow."""
        workflow_dir = self.project_root / '.github' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)
        
        frontend_install = "npm install" if analysis['frontend'].get('exists') else "echo 'No frontend'"
        backend_install = "pip install -q -r backend/requirements.txt" if analysis['backend'].get('exists') else "echo 'No backend'"
        frontend_test = "npm test" if analysis['frontend'].get('exists') else "echo 'No frontend tests'"
        backend_test = "pytest --tb=short" if analysis['backend'].get('exists') else "echo 'No backend tests'"
        frontend_build = "npm run build" if analysis['frontend'].get('exists') else "echo 'No frontend build'"
        
        workflow = f"""name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-and-build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up environment
        run: |
          python3 --version
          node --version
      
      - name: Install dependencies
        run: |
          {frontend_install}
          {backend_install}
      
      - name: Run tests
        run: |
          {frontend_test}
          {backend_test}
      
      - name: Build artifacts
        run: |
          {frontend_build}
      
      - name: Build Docker image
        run: |
          docker build -t {self.config.get('pipeline_name')}:latest .
      
      - name: Push to registry
        if: github.event_name == 'push'
        run: |
          echo "Push logic here"

  deploy:
    needs: test-and-build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Deploy to {self.config.get('target')}
        run: |
          echo "Deploying to {self.config.get('target')}..."
"""
        
        workflow_file = workflow_dir / 'pipeline.yml'
        workflow_file.write_text(workflow.strip())
        print(f"✅ Generated: {workflow_file.relative_to(self.project_root)}")
    
    def _generate_docker_compose(self, analysis: Dict) -> None:
        """Generate docker-compose.yml."""
        services = {}
        
        if analysis['frontend']['exists']:
            services['frontend'] = {
                'build': './frontend',
                'ports': [f"{analysis['frontend'].get('port', 3000)}:3000"],
                'environment': {'NODE_ENV': 'production'}
            }
        
        if analysis['backend']['exists']:
            services['backend'] = {
                'build': './backend',
                'ports': [f"{analysis['backend'].get('port', 8000)}:8000"],
                'environment': {
                    'DATABASE_URL': 'postgresql://user:password@db:5432/appdb',
                    'DEBUG': 'false'
                }
            }
        
        if services:
            compose = {'version': '3.9', 'services': services}
            compose_file = self.project_root / 'docker-compose.yml'
            with open(compose_file, 'w') as f:
                yaml.dump(compose, f, default_flow_style=False)
            print(f"✅ Generated: {compose_file.relative_to(self.project_root)}")
    
    def _generate_terraform(self, analysis: Dict) -> None:
        """Generate Terraform infrastructure code."""
        tf_dir = self.project_root / 'terraform'
        tf_dir.mkdir(parents=True, exist_ok=True)
        
        # main.tf
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

resource "aws_instance" "{self.config.get('pipeline_name').replace('-', '_')}" {{
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  
  tags = {{
    Name = "{self.config.get('pipeline_name')}-instance"
    Environment = var.environment
  }}
  
  vpc_security_group_ids = [aws_security_group.app.id]
}}

data "aws_ami" "ubuntu" {{
  most_recent = true
  owners      = ["099720109477"]  # Canonical
  
  filter {{
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }}
}}

resource "aws_security_group" "app" {{
  name = "{self.config.get('pipeline_name')}-sg"
  
  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

output "instance_ip" {{
  value       = aws_instance.{self.config.get('pipeline_name').replace('-', '_')}.public_ip
  description = "Public IP of the application"
}}"""
        
        (tf_dir / 'main.tf').write_text(main_tf)
        
        # variables.tf
        vars_tf = """variable "aws_region" {
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
        
        (tf_dir / 'variables.tf').write_text(vars_tf)
        
        print(f"✅ Generated: {tf_dir.relative_to(self.project_root)}/")
    
    def _generate_readme(self, analysis: Dict) -> None:
        """Generate documentation."""
        frontend_status = "✅ " + analysis['frontend'].get('framework', 'Unknown') if analysis['frontend'].get('exists') else "❌ Not found"
        backend_status = "✅ " + analysis['backend'].get('framework', 'Unknown') if analysis['backend'].get('exists') else "❌ Not found"
        
        readme = f"""# {self.config.get('pipeline_name', 'Application')}

**Generated by AI DevOps Agent** on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📋 Project Overview

This project was automatically analyzed and configured for CI/CD deployment.

### Project Structure
- **Frontend**: {frontend_status} (Port {analysis['frontend'].get('port', 'N/A') if analysis['frontend'].get('exists') else 'N/A'})
- **Backend**: {backend_status} (Port {analysis['backend'].get('port', 'N/A') if analysis['backend'].get('exists') else 'N/A'})
- **Infrastructure**: Terraform + AWS EC2

## 🚀 Quick Start

### Local Development
```bash
# Install dependencies
npm install  # frontend
pip install -r backend/requirements.txt  # backend

# Run services
docker-compose up
```

### Deployment
```bash
# Initialize Terraform
cd terraform
terraform init

# Plan deployment
terraform plan

# Apply infrastructure
terraform apply
```

## 🔒 Security Findings

{self._format_security_findings(analysis['security'])}

## 📁 Generated Files

- `.github/workflows/pipeline.yml` - CI/CD pipeline
- `docker-compose.yml` - Container orchestration
- `terraform/` - Infrastructure as Code
- `README.md` - This file

## ✅ Next Steps

1. Review security findings and remediate high-priority items
2. Configure GitHub secrets for deployment
3. Push changes to trigger pipeline
4. Monitor deployment in Actions tab

---

*This project was automatically generated. Manual review recommended before production use.*
"""
        
        readme_file = self.project_root / 'README_GENERATED.md'
        readme_file.write_text(readme)
        print(f"✅ Generated: {readme_file.relative_to(self.project_root)}")
    
    def _format_security_findings(self, security: Dict) -> str:
        """Format security findings as markdown."""
        all_issues = security['frontend'] + security['backend'] + security['infrastructure']
        
        if not all_issues:
            return "✅ No critical security issues detected."
        
        markdown = ""
        for issue in all_issues[:5]:  # Top 5
            sev = issue.get('severity', '?')
            title = issue.get('issue', 'Unknown')
            fix = issue.get('fix', 'Review manually')
            markdown += f"\n- **[{sev}]** {title}\n  - Fix: {fix}"
        
        return markdown


class WorkflowOrchestrator:
    """Orchestrates execution modes and workflow."""
    
    def __init__(self, project_root: str, config_file: str, openai_token: Optional[str] = None):
        self.project_root = project_root
        self.config_file = config_file
        self.openai_token = openai_token
        self.analyzer = ProjectAnalyzer(project_root, openai_token)
        self.generator = PipelineGenerator(project_root, config_file, openai_token)
    
    def run(self, mode: str) -> bool:
        """Execute workflow in specified mode."""
        
        if mode == 'analyze-only':
            return self.analyze_only()
        elif mode == 'generate':
            return self.generator.generate()
        elif mode == 'generate-and-commit':
            return self.generate_and_commit()
        elif mode == 'suggest-changes':
            return self.suggest_changes()
        else:
            print(f"❌ Unknown mode: {mode}")
            return False
    
    def analyze_only(self) -> bool:
        """Run analysis only."""
        print("🔍 Running analysis...\n")
        analysis = self.analyzer.analyze()
        self._print_analysis(analysis)
        return True
    
    def generate_and_commit(self) -> bool:
        """Generate and commit changes."""
        if not self.generator.generate():
            return False
        
        try:
            subprocess.run(['git', 'add', '.'], cwd=self.project_root, check=True)
            subprocess.run(
                ['git', 'commit', '-m', 'AI: Generated CI/CD pipeline'],
                cwd=self.project_root,
                check=True
            )
            print("✅ Changes committed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Git commit failed: {e}")
            return True  # Generation succeeded even if commit failed
    
    def suggest_changes(self) -> bool:
        """Generate suggestions report."""
        print("📝 Generating suggestions...\n")
        analysis = self.analyzer.analyze()
        
        suggestions = self._create_suggestions(analysis)
        
        output_file = Path(self.project_root) / 'SUGGESTIONS.md'
        output_file.write_text(suggestions)
        print(f"✅ Suggestions written to: {output_file.relative_to(self.project_root)}")
        return True
    
    def _create_suggestions(self, analysis: Dict) -> str:
        """Create suggestions markdown from analysis."""
        md = f"""# AI DevOps Agent - Suggestions

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 🔍 Analysis Results

### Frontend Status
{self._format_component_status(analysis['frontend'])}

### Backend Status
{self._format_component_status(analysis['backend'])}

## 🔒 Security Recommendations

{self._format_security_recommendations(analysis['security'])}

## 📋 Infrastructure

- Terraform: {'✅ Exists' if analysis['infrastructure']['terraform_exists'] else '❌ Missing'}
- Docker: {'✅ Configured' if analysis['docker']['dockerfiles'] else '❌ Not configured'}
- Git Repository: {'✅ Yes' if analysis['git']['is_repo'] else '❌ No'}

## ✅ Recommended Actions

1. **Address High-Severity Security Issues** - See security recommendations above
2. **Add/Update Tests** - Increase test coverage for frontend and backend
3. **Configure CI/CD** - Use generated pipeline files as starting point
4. **Deploy Infrastructure** - Apply generated Terraform configuration
5. **Document Configuration** - Update README with deployment instructions

---

*This is an automated analysis. Manual review recommended.*
"""
        return md
    
    def _format_component_status(self, component: Dict) -> str:
        """Format component status."""
        if not component.get('exists'):
            return "❌ Not found"
        
        return f"""✅ Detected
- Type: {component.get('type', component.get('language', 'Unknown'))}
- Framework: {component.get('framework', 'Generic')}
- Port: {component.get('port', 'N/A')}"""
    
    def _format_security_recommendations(self, security: Dict) -> str:
        """Format security recommendations."""
        all_issues = security['frontend'] + security['backend'] + security['infrastructure']
        
        if not all_issues:
            return "✅ No critical security issues detected."
        
        high = [i for i in all_issues if i.get('severity') == 'HIGH']
        medium = [i for i in all_issues if i.get('severity') == 'MEDIUM']
        
        md = f"**High Severity**: {len(high)} | **Medium Severity**: {len(medium)}\n\n"
        
        for issue in high[:3]:
            md += f"### 🔴 {issue.get('issue', 'Issue')}\n"
            md += f"- File: {issue.get('file', 'N/A')}\n"
            md += f"- Fix: {issue.get('fix', 'Manual review needed')}\n\n"
        
        return md
    
    def _print_analysis(self, analysis: Dict) -> None:
        """Pretty-print analysis results."""
        print("=" * 60)
        print("PROJECT ANALYSIS RESULTS")
        print("=" * 60)
        
        print(f"\n📱 Frontend: {self._format_component_status(analysis['frontend'])}")
        print(f"\n🔧 Backend: {self._format_component_status(analysis['backend'])}")
        print(f"\n☁️  Infrastructure: Terraform: {analysis['infrastructure']['terraform_exists']}")
        print(f"\n🐳 Docker: {len(analysis['docker']['dockerfiles'])} Dockerfile(s)")
        
        print("\n🔒 Security Summary:")
        all_issues = analysis['security']['frontend'] + analysis['security']['backend'] + analysis['security']['infrastructure']
        if all_issues:
            high = len([i for i in all_issues if i.get('severity') == 'HIGH'])
            medium = len([i for i in all_issues if i.get('severity') == 'MEDIUM'])
            print(f"  - HIGH: {high}")
            print(f"  - MEDIUM: {medium}")
        else:
            print("  ✅ No issues detected")
        
        print("\n" + "=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Simplified AI DevOps Agent'
    )
    
    parser.add_argument('--project-root', default='.', help='Project root directory')
    parser.add_argument('--config-file', default='pipeline_request.txt', help='Config file')
    parser.add_argument('--openai-token', help='OpenAI API token')
    parser.add_argument('--mode', choices=['analyze-only', 'generate', 'generate-and-commit', 'suggest-changes'],
                       default='generate', help='Execution mode')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    # For backward compatibility with old CLI interface
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze the project')
    parser.add_argument('--auto-commit', action='store_true', help='Automatically commit changes')
    parser.add_argument('--suggest-changes', action='store_true', help='Suggest changes instead of generating')
    
    args = parser.parse_args()
    
    print("🤖 AI DevOps Agent (Simplified)")
    print("=" * 50)
    
    try:
        openai_token = args.openai_token or os.getenv('OPENAI_API_TOKEN')
        orchestrator = WorkflowOrchestrator(args.project_root, args.config_file, openai_token)
        
        # Handle backward compatibility with old CLI flags
        if args.analyze_only:
            mode = 'analyze-only'
        elif args.suggest_changes:
            mode = 'suggest-changes'
        elif args.auto_commit:
            mode = 'generate-and-commit'
        else:
            mode = args.mode
        
        success = orchestrator.run(mode)
        
        if success:
            print("\n✅ Workflow completed successfully")
            sys.exit(0)
        else:
            print("\n❌ Workflow failed")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n⚠️  Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
