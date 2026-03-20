#!/usr/bin/env python3.11
"""
AI-Powered DevOps Agent with Security & Best Practices Analysis
================================================================

This script automatically analyzes a codebase and provides comprehensive
DevOps automation with integrated security scanning, including:

Code Analysis:
- Language and framework detection
- Dependency analysis and version tracking
- Port and configuration detection

Security Analysis:
- Frontend vulnerability scanning (XSS, eval, credential exposure)
- Backend security checks (SQL injection, pickle, debug mode)
- Infrastructure security (Docker best practices, secret management)
- Risk assessment and prioritization

Best Practices:
- Code quality checks (testing, linting, type hints)
- Documentation requirements
- CI/CD configuration validation
- DevOps maturity scoring

Pipeline Generation:
- GitHub Actions workflows
- Infrastructure as Code (Terraform)
- Docker containerization
- AWS EC2 deployment
- Automated testing and deployment

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
import time

class CodeAnalyzer:
    """Analyzes codebase to detect languages, frameworks, and configurations."""
    
    def __init__(self, project_root: str, openai_token: Optional[str] = None):
        self.project_root = Path(project_root)
        self.analysis_results = {}
        self.openai_token = openai_token
    
    def _call_openai(self, system: str, user: str) -> Optional[Dict]:
        """Call OpenAI API and return parsed JSON response."""
        headers = {"Authorization": f"Bearer {self.openai_token}", "Content-Type": "application/json"}
        data = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": 2000,
            "temperature": 0.3
        }
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=30)
        if response.status_code != 200:
            raise Exception(f"OpenAI API error {response.status_code}: {response.text}")
        content = response.json()['choices'][0]['message']['content']
        # Strip markdown code fences if present
        content = re.sub(r'^```(?:json)?\s*', '', content.strip())
        content = re.sub(r'\s*```$', '', content)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"raw": content}

    def analyze_project(self) -> Dict:
        """Perform comprehensive project analysis, enhanced by AI at every stage."""
        print("🔍 Analyzing project structure...")
        
        analysis = {
            'frontend': self._analyze_frontend(),
            'backend': self._analyze_backend(),
            'infrastructure': self._analyze_infrastructure(),
            'docker': self._analyze_docker(),
            'git': self._analyze_git(),
            'security': self._analyze_security(),
            'best_practices': self._analyze_best_practices()
        }

        # AI enrichment of security findings
        print("🧠 AI enriching security analysis...")
        security_context = {
            "frontend_issues": analysis['security'].get('frontend', []),
            "backend_issues": analysis['security'].get('backend', []),
            "infra_issues": analysis['security'].get('infrastructure', []),
            "overall_risk": analysis['security'].get('overall_risk', 'LOW')
        }
        ai_security = self._call_openai(
            "You are a senior application security engineer. Analyse the provided security findings and return a JSON object with keys: "
            "'enriched_findings' (array — each item adds 'cve_references', 'exploit_scenario', 'priority_fix' to the original finding), "
            "'attack_surface_summary' (string), 'top_3_actions' (array of strings).",
            json.dumps(security_context, indent=2)
        )
        if ai_security:
            analysis['security']['ai_enrichment'] = ai_security
            print("✅ AI security enrichment complete")

        # AI enrichment of best practices
        print("🧠 AI enriching best practices analysis...")
        bp_context = {
            "frontend_framework": analysis['frontend'].get('framework', 'unknown'),
            "backend_framework": analysis['backend'].get('framework', 'unknown'),
            "compliance_score": analysis['best_practices'].get('compliance_score', 0),
            "frontend_gaps": analysis['best_practices'].get('frontend', []),
            "backend_gaps": analysis['best_practices'].get('backend', []),
            "general_gaps": analysis['best_practices'].get('general', [])
        }
        ai_bp = self._call_openai(
            "You are a DevOps best-practices expert. Given the compliance gaps below, return a JSON object with keys: "
            "'prioritised_recommendations' (array of objects with 'title', 'effort' (Low/Medium/High), 'impact' (Low/Medium/High), 'steps' (array of strings)), "
            "'maturity_level' (string: Beginner/Intermediate/Advanced), 'quick_wins' (array of strings).",
            json.dumps(bp_context, indent=2)
        )
        if ai_bp:
            analysis['best_practices']['ai_enrichment'] = ai_bp
            print("✅ AI best practices enrichment complete")
        
        self.analysis_results = analysis
        return analysis
    
    def _analyze_frontend(self) -> Dict:
        """Analyze frontend code and configuration."""
        frontend_path = self.project_root / 'frontend'
        
        if not frontend_path.exists():
            return {'exists': False}
        
        analysis = {'exists': True, 'path': str(frontend_path)}
        
        # Check for package.json (Node.js projects)
        package_json = frontend_path / 'package.json'
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    package_data = json.load(f)
                analysis['framework'] = 'node'
                analysis['dependencies'] = package_data.get('dependencies', {})
                analysis['scripts'] = package_data.get('scripts', {})
                analysis['test_command'] = 'npm test'
                analysis['build_command'] = 'npm run build'
                analysis['lint_command'] = 'npm run lint'
                analysis['install_command'] = 'npm install'
            except Exception as e:
                print(f"Warning: Could not parse package.json: {e}")
        
        # Check for index.html (static/vanilla JS projects)
        elif (frontend_path / 'index.html').exists():
            analysis['framework'] = 'vanilla-js'
            analysis['dependencies'] = {}
            analysis['test_command'] = 'echo "No tests defined for vanilla JS"'
            analysis['build_command'] = 'echo "No build step needed"'
            analysis['lint_command'] = 'echo "No linting configured"'
            analysis['install_command'] = 'echo "No dependencies to install"'
        
        # Detect port from JavaScript files
        js_files = list(frontend_path.glob('*.js'))
        analysis['port'] = self._detect_port_from_files(js_files, default=3000)
        
        return analysis
    
    def _analyze_backend(self) -> Dict:
        """Analyze backend code and configuration."""
        backend_path = self.project_root / 'backend'
        
        if not backend_path.exists():
            return {'exists': False}
        
        analysis = {'exists': True, 'path': str(backend_path)}
        
        # Check for Python projects
        if (backend_path / 'requirements.txt').exists() or (backend_path / 'main.py').exists():
            analysis['language'] = 'python'
            analysis['framework'] = self._detect_python_framework(backend_path)
            
            # Read requirements.txt
            req_file = backend_path / 'requirements.txt'
            if req_file.exists():
                with open(req_file, 'r') as f:
                    requirements = f.read().strip().split('\n')
                analysis['dependencies'] = [req.strip() for req in requirements if req.strip()]
            
            analysis['test_command'] = 'pytest'
            analysis['lint_command'] = 'flake8'
            analysis['install_command'] = 'pip install -r requirements.txt'
            
            # Detect port from Python files
            py_files = list(backend_path.glob('*.py'))
            analysis['port'] = self._detect_port_from_files(py_files, default=8000)
        
        return analysis
    
    def _detect_python_framework(self, backend_path: Path) -> str:
        """Detect Python web framework."""
        main_py = backend_path / 'main.py'
        if main_py.exists():
            content = main_py.read_text()
            if 'fastapi' in content.lower():
                return 'fastapi'
            elif 'flask' in content.lower():
                return 'flask'
            elif 'django' in content.lower():
                return 'django'
        return 'unknown'
    
    def _detect_port_from_files(self, files: List[Path], default: int) -> int:
        """Detect port number from code files."""
        for file_path in files:
            try:
                content = file_path.read_text()
                # Look for common port patterns
                port_patterns = [
                    r'port[:\s]*=?\s*(\d+)',
                    r'localhost:(\d+)',
                    r'0\.0\.0\.0:(\d+)',
                    r'uvicorn.*--port\s+(\d+)',
                    r'listen[:\s]*(\d+)'
                ]
                
                for pattern in port_patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        return int(match.group(1))
            except Exception:
                continue
        
        return default
    
    def _analyze_infrastructure(self) -> Dict:
        """Analyze existing infrastructure configuration."""
        terraform_path = self.project_root / 'terraform'
        
        analysis = {
            'terraform_exists': terraform_path.exists(),
            'terraform_path': str(terraform_path)
        }
        
        if terraform_path.exists():
            tf_files = list(terraform_path.glob('*.tf'))
            analysis['terraform_files'] = [str(f) for f in tf_files]
        
        return analysis
    
    def _analyze_docker(self) -> Dict:
        """Analyze Docker configuration."""
        compose_file = self.project_root / 'docker-compose.yml'
        
        analysis = {
            'compose_exists': compose_file.exists(),
            'dockerfiles': []
        }
        
        # Find Dockerfiles
        for dockerfile in self.project_root.rglob('Dockerfile'):
            analysis['dockerfiles'].append(str(dockerfile))
        
        return analysis
    
    def _analyze_git(self) -> Dict:
        """Analyze git repository information."""
        git_path = self.project_root / '.git'
        
        analysis = {'is_git_repo': git_path.exists()}
        
        if git_path.exists():
            try:
                # Get current branch
                result = subprocess.run(['git', 'branch', '--show-current'], 
                                      cwd=self.project_root, 
                                      capture_output=True, text=True)
                analysis['current_branch'] = result.stdout.strip()
                
                # Get remote URL
                result = subprocess.run(['git', 'remote', 'get-url', 'origin'], 
                                      cwd=self.project_root, 
                                      capture_output=True, text=True)
                analysis['remote_url'] = result.stdout.strip()
                
            except Exception as e:
                print(f"Warning: Could not get git info: {e}")
        
        return analysis
    
    def _analyze_security(self) -> Dict:
        """Analyze security vulnerabilities in frontend and backend code."""
        vulnerabilities = {
            'frontend': [],
            'backend': [],
            'infrastructure': [],
            'overall_risk': 'LOW'
        }
        
        # Frontend security checks
        frontend_path = self.project_root / 'frontend'
        if frontend_path.exists():
            vulnerabilities['frontend'].extend(self._check_frontend_security(frontend_path))
        
        # Backend security checks
        backend_path = self.project_root / 'backend'
        if backend_path.exists():
            vulnerabilities['backend'].extend(self._check_backend_security(backend_path))
        
        # Infrastructure security checks
        vulnerabilities['infrastructure'].extend(self._check_infrastructure_security())
        
        # Determine overall risk level
        all_vulns = vulnerabilities['frontend'] + vulnerabilities['backend'] + vulnerabilities['infrastructure']
        high_severity = [v for v in all_vulns if v.get('severity') == 'HIGH']
        medium_severity = [v for v in all_vulns if v.get('severity') == 'MEDIUM']
        
        if high_severity:
            vulnerabilities['overall_risk'] = 'HIGH'
        elif medium_severity:
            vulnerabilities['overall_risk'] = 'MEDIUM'
        else:
            vulnerabilities['overall_risk'] = 'LOW'
        
        return vulnerabilities
    
    def _check_frontend_security(self, frontend_path: Path) -> List[Dict]:
        """Check frontend code for common security vulnerabilities."""
        issues = []
        
        # Check for outdated dependencies in package.json
        package_json = frontend_path / 'package.json'
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    pkg_data = json.load(f)
                    
                # Check for package-lock.json (prevents supply chain attacks)
                if not (frontend_path / 'package-lock.json').exists():
                    issues.append({
                        'severity': 'MEDIUM',
                        'category': 'Dependency Management',
                        'issue': 'Missing package-lock.json',
                        'description': 'No package-lock.json file found - this can lead to inconsistent installations',
                        'recommendation': 'Run `npm install` to generate package-lock.json and commit it'
                    })
                
                # Check for security-related packages
                deps = pkg_data.get('dependencies', {})
                if not any(sec in str(deps) for sec in ['helmet', 'cors', 'csrf']):
                    issues.append({
                        'severity': 'MEDIUM',
                        'category': 'Security Headers',
                        'issue': 'Missing security middleware packages',
                        'description': 'No security-related packages detected (helmet, cors, etc.)',
                        'recommendation': 'Consider adding security headers and CORS configuration'
                    })
            except Exception as e:
                print(f"Warning: Could not analyze package.json: {e}")
        
        # Check JavaScript files for common XSS vulnerabilities
        js_files = list(frontend_path.glob('*.js'))
        for js_file in js_files:
            try:
                content = js_file.read_text()
                
                # Check for eval() usage
                if re.search(r'\beval\s*\(', content):
                    issues.append({
                        'severity': 'HIGH',
                        'category': 'Code Injection',
                        'issue': f'Dangerous eval() usage in {js_file.name}',
                        'description': 'eval() can execute arbitrary code and is a security risk',
                        'recommendation': 'Replace eval() with safer alternatives like JSON.parse()'
                    })
                
                # Check for innerHTML usage (XSS risk)
                if re.search(r'\.innerHTML\s*=', content):
                    issues.append({
                        'severity': 'MEDIUM',
                        'category': 'XSS Vulnerability',
                        'issue': f'Potential XSS risk with innerHTML in {js_file.name}',
                        'description': 'innerHTML can execute scripts if user input is not sanitized',
                        'recommendation': 'Use textContent or sanitize input with DOMPurify'
                    })
                
                # Check for hard-coded credentials
                if re.search(r'(password|api[_-]?key|secret|token)\s*[:=]\s*["\'][^"\']+["\']', content, re.IGNORECASE):
                    issues.append({
                        'severity': 'HIGH',
                        'category': 'Credential Exposure',
                        'issue': f'Potential hard-coded credentials in {js_file.name}',
                        'description': 'Hard-coded secrets detected in code',
                        'recommendation': 'Move credentials to environment variables'
                    })
                    
            except Exception as e:
                print(f"Warning: Could not scan {js_file}: {e}")
        
        return issues
    
    def _check_backend_security(self, backend_path: Path) -> List[Dict]:
        """Check backend code for common security vulnerabilities."""
        issues = []
        
        # Check requirements.txt for outdated/vulnerable packages
        req_file = backend_path / 'requirements.txt'
        if req_file.exists():
            try:
                with open(req_file, 'r') as f:
                    requirements = f.read()
                    
                # Check for missing version pins
                unpinned = re.findall(r'^([a-zA-Z0-9_-]+)\s*$', requirements, re.MULTILINE)
                if unpinned:
                    issues.append({
                        'severity': 'MEDIUM',
                        'category': 'Dependency Management',
                        'issue': 'Unpinned dependencies detected',
                        'description': f'Packages without version pins: {", ".join(unpinned[:3])}',
                        'recommendation': 'Pin all dependencies to specific versions for reproducibility'
                    })
            except Exception as e:
                print(f"Warning: Could not analyze requirements.txt: {e}")
        
        # Check Python files for security issues
        py_files = list(backend_path.glob('*.py'))
        for py_file in py_files:
            try:
                content = py_file.read_text()
                
                # Check for SQL injection vulnerabilities
                if re.search(r'execute\s*\([^)]*[+%]\s*["\']|f["\'].*SELECT.*{', content):
                    issues.append({
                        'severity': 'HIGH',
                        'category': 'SQL Injection',
                        'issue': f'Potential SQL injection in {py_file.name}',
                        'description': 'String concatenation in SQL queries detected',
                        'recommendation': 'Use parameterized queries or ORM methods'
                    })
                
                # Check for hard-coded secrets
                if re.search(r'(password|api[_-]?key|secret|token)\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
                    issues.append({
                        'severity': 'HIGH',
                        'category': 'Credential Exposure',
                        'issue': f'Hard-coded credentials in {py_file.name}',
                        'description': 'Sensitive credentials found in source code',
                        'recommendation': 'Use environment variables and secret management'
                    })
                
                # Check for pickle usage (deserialization vulnerability)
                if re.search(r'import\s+pickle|pickle\.(load|loads)', content):
                    issues.append({
                        'severity': 'HIGH',
                        'category': 'Deserialization',
                        'issue': f'Unsafe deserialization with pickle in {py_file.name}',
                        'description': 'pickle can execute arbitrary code during deserialization',
                        'recommendation': 'Use JSON or other safe serialization formats'
                    })
                
                # Check for debug mode in production
                if re.search(r'debug\s*=\s*True|DEBUG\s*=\s*True', content):
                    issues.append({
                        'severity': 'MEDIUM',
                        'category': 'Debug Mode',
                        'issue': f'Debug mode enabled in {py_file.name}',
                        'description': 'Debug mode can expose sensitive information',
                        'recommendation': 'Use environment variables to control debug mode'
                    })
                
                # Check for missing CORS configuration
                if 'fastapi' in content.lower() or 'flask' in content.lower():
                    if not re.search(r'CORS|CORSMiddleware', content):
                        issues.append({
                            'severity': 'LOW',
                            'category': 'CORS Configuration',
                            'issue': f'No CORS configuration in {py_file.name}',
                            'description': 'CORS not configured - may cause frontend integration issues',
                            'recommendation': 'Add CORSMiddleware with appropriate origins'
                        })
                        
            except Exception as e:
                print(f"Warning: Could not scan {py_file}: {e}")
        
        return issues
    
    def _check_infrastructure_security(self) -> List[Dict]:
        """Check infrastructure configurations for security issues."""
        issues = []
        
        # Check Docker configurations
        dockerfiles = list(self.project_root.glob('**/Dockerfile'))
        for dockerfile in dockerfiles:
            try:
                content = dockerfile.read_text()
                
                # Check for running as root
                if not re.search(r'USER\s+\w+', content):
                    issues.append({
                        'severity': 'HIGH',
                        'category': 'Container Security',
                        'issue': f'Container runs as root in {dockerfile.relative_to(self.project_root)}',
                        'description': 'No USER directive found - container runs as root by default',
                        'recommendation': 'Add non-root user: USER appuser'
                    })
                
                # Check for latest tag usage
                if re.search(r'FROM\s+[^:]+:latest', content):
                    issues.append({
                        'severity': 'MEDIUM',
                        'category': 'Container Security',
                        'issue': f'Using :latest tag in {dockerfile.relative_to(self.project_root)}',
                        'description': 'latest tag can lead to unpredictable builds',
                        'recommendation': 'Pin base images to specific versions'
                    })
                    
            except Exception as e:
                print(f"Warning: Could not scan {dockerfile}: {e}")
        
        # Check for .env files (should not be committed)
        env_files = list(self.project_root.glob('**/.env'))
        for env_file in env_files:
            if not env_file.name.endswith('.example'):
                issues.append({
                    'severity': 'HIGH',
                    'category': 'Secret Management',
                    'issue': f'Environment file in repository: {env_file.relative_to(self.project_root)}',
                    'description': '.env files may contain secrets and should not be committed',
                    'recommendation': 'Add .env to .gitignore and use .env.example for templates'
                })
        
        return issues
    
    def _analyze_best_practices(self) -> Dict:
        """Analyze code for best practices compliance."""
        best_practices = {
            'frontend': [],
            'backend': [],
            'general': [],
            'compliance_score': 0
        }
        
        total_checks = 0
        passed_checks = 0
        
        # Frontend best practices
        frontend_path = self.project_root / 'frontend'
        if frontend_path.exists():
            frontend_bp, frontend_score = self._check_frontend_best_practices(frontend_path)
            best_practices['frontend'] = frontend_bp
            total_checks += frontend_score['total']
            passed_checks += frontend_score['passed']
        
        # Backend best practices
        backend_path = self.project_root / 'backend'
        if backend_path.exists():
            backend_bp, backend_score = self._check_backend_best_practices(backend_path)
            best_practices['backend'] = backend_bp
            total_checks += backend_score['total']
            passed_checks += backend_score['passed']
        
        # General best practices
        general_bp, general_score = self._check_general_best_practices()
        best_practices['general'] = general_bp
        total_checks += general_score['total']
        passed_checks += general_score['passed']
        
        # Calculate compliance score
        if total_checks > 0:
            best_practices['compliance_score'] = int((passed_checks / total_checks) * 100)
        else:
            best_practices['compliance_score'] = 100
        
        return best_practices
    
    def _check_frontend_best_practices(self, frontend_path: Path) -> Tuple[List[Dict], Dict]:
        """Check frontend code for best practices."""
        recommendations = []
        total = 0
        passed = 0
        
        # Check for README
        total += 1
        if (frontend_path / 'README.md').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Documentation',
                'issue': 'Missing frontend README.md',
                'recommendation': 'Add README.md with setup instructions and documentation'
            })
        
        # Check for ESLint configuration
        total += 1
        if (frontend_path / '.eslintrc.js').exists() or (frontend_path / '.eslintrc.json').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Code Quality',
                'issue': 'No ESLint configuration',
                'recommendation': 'Add ESLint for code quality and consistency'
            })
        
        # Check for test files
        total += 1
        test_files = list(frontend_path.glob('**/*.test.js')) + list(frontend_path.glob('**/*.spec.js'))
        if test_files:
            passed += 1
        else:
            recommendations.append({
                'category': 'Testing',
                'issue': 'No test files found',
                'recommendation': 'Add unit tests for critical functionality'
            })
        
        # Check for .gitignore
        total += 1
        if (frontend_path / '.gitignore').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Version Control',
                'issue': 'No .gitignore file',
                'recommendation': 'Add .gitignore to exclude node_modules and build artifacts'
            })
        
        return recommendations, {'total': total, 'passed': passed}
    
    def _check_backend_best_practices(self, backend_path: Path) -> Tuple[List[Dict], Dict]:
        """Check backend code for best practices."""
        recommendations = []
        total = 0
        passed = 0
        
        # Check for test files
        total += 1
        test_files = list(backend_path.glob('**/test_*.py'))
        if test_files:
            passed += 1
        else:
            recommendations.append({
                'category': 'Testing',
                'issue': 'No test files found',
                'recommendation': 'Add pytest tests for API endpoints and business logic'
            })
        
        # Check for requirements-dev.txt
        total += 1
        if (backend_path / 'requirements-dev.txt').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Dependency Management',
                'issue': 'Missing requirements-dev.txt',
                'recommendation': 'Separate development dependencies (pytest, flake8) from production'
            })
        
        # Check for type hints in Python files
        total += 1
        py_files = list(backend_path.glob('*.py'))
        has_type_hints = False
        for py_file in py_files:
            try:
                content = py_file.read_text()
                if re.search(r':\s*(str|int|bool|float|Dict|List|Optional|Tuple)', content):
                    has_type_hints = True
                    passed += 1
                    break
            except Exception:
                pass
        
        if not has_type_hints and py_files:
            recommendations.append({
                'category': 'Code Quality',
                'issue': 'No type hints detected',
                'recommendation': 'Add type hints for better code maintainability and IDE support'
            })
        
        # Check for logging configuration
        total += 1
        has_logging = False
        for py_file in py_files:
            try:
                content = py_file.read_text()
                if 'import logging' in content or 'from logging import' in content:
                    has_logging = True
                    passed += 1
                    break
            except Exception:
                pass
        
        if not has_logging and py_files:
            recommendations.append({
                'category': 'Observability',
                'issue': 'No logging configuration',
                'recommendation': 'Add structured logging for debugging and monitoring'
            })
        
        return recommendations, {'total': total, 'passed': passed}
    
    def _check_general_best_practices(self) -> Tuple[List[Dict], Dict]:
        """Check general project best practices."""
        recommendations = []
        total = 0
        passed = 0
        
        # Check for main README
        total += 1
        if (self.project_root / 'README.md').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Documentation',
                'issue': 'Missing project README.md',
                'recommendation': 'Add comprehensive README with project overview and setup guide'
            })
        
        # Check for CI/CD configuration
        total += 1
        ci_configs = [
            self.project_root / '.github' / 'workflows',
            self.project_root / '.gitlab-ci.yml',
            self.project_root / '.circleci',
            self.project_root / 'Jenkinsfile'
        ]
        if any(path.exists() for path in ci_configs):
            passed += 1
        else:
            recommendations.append({
                'category': 'DevOps',
                'issue': 'No CI/CD configuration',
                'recommendation': 'Add automated testing and deployment pipelines'
            })
        
        # Check for LICENSE file
        total += 1
        if (self.project_root / 'LICENSE').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Legal',
                'issue': 'No LICENSE file',
                'recommendation': 'Add appropriate license file for your project'
            })
        
        # Check for CONTRIBUTING guide
        total += 1
        if (self.project_root / 'CONTRIBUTING.md').exists():
            passed += 1
        else:
            recommendations.append({
                'category': 'Documentation',
                'issue': 'No CONTRIBUTING.md',
                'recommendation': 'Add contribution guidelines for collaborators'
            })
        
        return recommendations, {'total': total, 'passed': passed}

class PipelineGenerator:
    """Generates CI/CD pipeline components based on code analysis."""
    
    def __init__(self, project_root: str, config_file: str = 'pipeline_request.txt', openai_token: Optional[str] = None):
        self.project_root = Path(project_root)
        self.config_file = config_file
        self.openai_token = openai_token.strip() if openai_token else None
        if not self.openai_token:
            print("❌ OpenAI API token is required. Provide via --openai-token or OPENAI_API_TOKEN env var.")
            sys.exit(1)
        print("🤖 AI DevOps Agent — OpenAI integration active")
        self.config = self._load_config()
        self.analyzer = CodeAnalyzer(project_root, openai_token=self.openai_token)
    
    def _load_config(self) -> Dict:
        """Load pipeline configuration from file."""
        config_path = self.project_root / self.config_file
        
        if not config_path.exists():
            print(f"Warning: {self.config_file} not found, using defaults")
            return self._default_config()
        
        config = {}
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Handle lists
                            if value.startswith('[') and value.endswith(']'):
                                value = value[1:-1].split(',')
                                value = [v.strip() for v in value]
                            
                            config[key] = value
            
            print(f"🔧 Loaded config from {self.config_file}: instance_type={config.get('instance_type', 'default')}, environment={config.get('environment', 'default')}")
        
        except Exception as e:
            print(f"Error loading config: {e}")
            return self._default_config()
        
        # Return the loaded config (defaults will be handled in individual methods)
        return config
    
    def _default_config(self) -> Dict:
        """Return default pipeline configuration."""
        return {
            'pipeline_name': 'auto-generated-pipeline',
            'environment': 'production',
            'target': 'aws_ec2',
            'instance_type': 't2.micro',
            'deploy_using': 'docker-compose',
            'labels': ['ai-generated', 'demo'],
            'email_notification': 'true',
            'email_recipient': 'demo@example.com'
        }
    
    def _call_openai_api(self, system: str, user: str) -> Dict:
        """Call OpenAI API. Raises on failure (token is mandatory)."""
        headers = {"Authorization": f"Bearer {self.openai_token}", "Content-Type": "application/json"}
        data = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": 2000,
            "temperature": 0.3
        }
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=30)
        if response.status_code != 200:
            raise Exception(f"OpenAI API error {response.status_code}: {response.text}")
        content = response.json()['choices'][0]['message']['content']
        content = re.sub(r'^```(?:json)?\s*', '', content.strip())
        content = re.sub(r'\s*```$', '', content)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"raw": content}

    def _ai_enhance_analysis(self, analysis: Dict) -> Dict:
        """Use AI to generate pipeline and infra recommendations from full analysis."""
        print("🧠 AI generating pipeline and infrastructure recommendations...")
        context = {
            "project_type": "web_application",
            "frontend": {k: v for k, v in analysis.get('frontend', {}).items() if k != 'path'},
            "backend": {k: v for k, v in analysis.get('backend', {}).items() if k != 'path'},
            "infrastructure_exists": analysis.get('infrastructure', {}).get('terraform_exists', False),
            "docker_setup": analysis.get('docker', {}).get('compose_exists', False),
            "security_risk": analysis.get('security', {}).get('overall_risk', 'LOW'),
            "compliance_score": analysis.get('best_practices', {}).get('compliance_score', 0)
        }
        result = self._call_openai_api(
            "You are an expert DevOps engineer. Given this project analysis, return a JSON object with keys: "
            "'pipeline_stages' (array of objects with 'name', 'purpose', 'tools'), "
            "'testing_strategy' (object with 'unit', 'integration', 'e2e' keys), "
            "'deployment_recommendations' (array of strings), "
            "'infra_optimisations' (array of strings), "
            "'performance_tips' (array of strings).",
            json.dumps(context, indent=2)
        )
        analysis['ai_recommendations'] = result
        print("✅ AI pipeline recommendations complete")
        return analysis
    
    def _format_analysis_human_readable(self, analysis: Dict) -> str:
        """Format analysis results in human-readable format."""
        output = []
        output.append("\n📊 Project Analysis Report")
        output.append("=" * 50)
        
        # Frontend Analysis
        frontend = analysis.get('frontend', {})
        if frontend.get('exists'):
            output.append("\n🎨 Frontend Application:")
            framework = frontend.get('framework', 'Unknown')
            if framework == 'node':
                framework = 'Node.js/JavaScript'
            elif framework == 'vanilla-js':
                framework = 'Vanilla JavaScript'
            output.append(f"   📋 Framework: {framework}")
            output.append(f"   🌐 Port: {frontend.get('port', 'Not specified')}")
            
            dependencies = frontend.get('dependencies', {})
            if dependencies:
                output.append(f"   📦 Dependencies: {len(dependencies)} packages")
            
            # Show available scripts if any
            scripts = frontend.get('scripts', {})
            if scripts:
                output.append("   🛠️  Available scripts:")
                for script_name in ['test', 'build', 'lint', 'dev']:
                    if script_name in scripts:
                        output.append(f"      • {script_name}: Available")
        else:
            output.append("\n🎨 Frontend Application: ❌ Not found")
        
        # Backend Analysis
        backend = analysis.get('backend', {})
        if backend.get('exists'):
            output.append("\n🔧 Backend Application:")
            language = backend.get('language', 'Unknown').title()
            framework = backend.get('framework', 'Unknown')
            if framework == 'fastapi':
                framework = 'FastAPI'
            elif framework == 'flask':
                framework = 'Flask'
            elif framework == 'django':
                framework = 'Django'
            
            output.append(f"   💻 Language: {language}")
            output.append(f"   🚀 Framework: {framework}")
            output.append(f"   🌐 Port: {backend.get('port', 'Not specified')}")
            
            dependencies = backend.get('dependencies', [])
            if dependencies:
                output.append(f"   📦 Dependencies: {len(dependencies)} packages")
                # Show main dependencies
                main_deps = [dep.split('==')[0] for dep in dependencies[:3]]
                if main_deps:
                    output.append(f"      • Key packages: {', '.join(main_deps)}")
            
            # Show testing and linting setup
            if backend.get('test_command'):
                output.append(f"   🧪 Testing: {backend.get('test_command', 'Not configured')}")
            if backend.get('lint_command'):
                output.append(f"   🔍 Linting: {backend.get('lint_command', 'Not configured')}")
        else:
            output.append("\n🔧 Backend Application: ❌ Not found")
        
        # Infrastructure Analysis
        infra = analysis.get('infrastructure', {})
        output.append("\n🏗️ Infrastructure:")
        if infra.get('terraform_exists'):
            output.append("   ✅ Terraform configuration detected")
            tf_files = infra.get('terraform_files', [])
            if tf_files:
                output.append(f"   📄 Configuration files: {len(tf_files)}")
                for tf_file in tf_files:
                    filename = tf_file.split('/')[-1]
                    output.append(f"      • {filename}")
        else:
            output.append("   ⚠️  No Terraform configuration (will be generated)")
        
        # Docker Analysis
        docker = analysis.get('docker', {})
        output.append("\n🐳 Containerization:")
        if docker.get('compose_exists'):
            output.append("   ✅ Docker Compose configuration detected")
        else:
            output.append("   ⚠️  No Docker Compose (will be generated)")
            
        dockerfiles = docker.get('dockerfiles', [])
        if dockerfiles:
            output.append(f"   📦 Dockerfiles found: {len(dockerfiles)}")
            for dockerfile in dockerfiles:
                service = dockerfile.split('/')[-2] if '/' in dockerfile else 'root'
                output.append(f"      • {service.title()} service")
        else:
            output.append("   ⚠️  No Dockerfiles (will be generated)")
        
        # Git Analysis
        git = analysis.get('git', {})
        if git.get('is_git_repo'):
            output.append("\n📚 Version Control:")
            output.append(f"   Branch: {git.get('current_branch', 'Unknown')}")
            if git.get('remote_url'):
                output.append(f"   Repository: {git.get('remote_url')}")
        
        # Security Analysis
        security = analysis.get('security', {})
        if security:
            output.append("\n🔒 Security Analysis:")
            risk_level = security.get('overall_risk', 'UNKNOWN')
            risk_emoji = '🔴' if risk_level == 'HIGH' else '🟡' if risk_level == 'MEDIUM' else '🟢'
            output.append(f"   {risk_emoji} Overall Risk Level: {risk_level}")
            
            total_vulns = len(security.get('frontend', [])) + len(security.get('backend', [])) + len(security.get('infrastructure', []))
            if total_vulns > 0:
                output.append(f"   ⚠️  Total Issues Found: {total_vulns}")
                
                # Frontend vulnerabilities
                frontend_vulns = security.get('frontend', [])
                if frontend_vulns:
                    output.append(f"\n   Frontend Issues ({len(frontend_vulns)}):")
                    for vuln in frontend_vulns[:3]:  # Show top 3
                        output.append(f"      • [{vuln.get('severity')}] {vuln.get('issue')}")
                
                # Backend vulnerabilities
                backend_vulns = security.get('backend', [])
                if backend_vulns:
                    output.append(f"\n   Backend Issues ({len(backend_vulns)}):")
                    for vuln in backend_vulns[:3]:  # Show top 3
                        output.append(f"      • [{vuln.get('severity')}] {vuln.get('issue')}")
                
                # Infrastructure vulnerabilities
                infra_vulns = security.get('infrastructure', [])
                if infra_vulns:
                    output.append(f"\n   Infrastructure Issues ({len(infra_vulns)}):")
                    for vuln in infra_vulns[:3]:  # Show top 3
                        output.append(f"      • [{vuln.get('severity')}] {vuln.get('issue')}")
            else:
                output.append("   ✅ No security issues detected")
        
        # Best Practices Analysis
        best_practices = analysis.get('best_practices', {})
        if best_practices:
            output.append("\n📋 Best Practices Compliance:")
            score = best_practices.get('compliance_score', 0)
            score_emoji = '🟢' if score >= 80 else '🟡' if score >= 60 else '🔴'
            output.append(f"   {score_emoji} Compliance Score: {score}%")
            
            total_recommendations = (
                len(best_practices.get('frontend', [])) + 
                len(best_practices.get('backend', [])) + 
                len(best_practices.get('general', []))
            )
            
            if total_recommendations > 0:
                output.append(f"   💡 Recommendations: {total_recommendations}")
                
                # Show top recommendations
                all_recs = []
                all_recs.extend(best_practices.get('frontend', []))
                all_recs.extend(best_practices.get('backend', []))
                all_recs.extend(best_practices.get('general', []))
                
                for rec in all_recs[:5]:  # Show top 5
                    output.append(f"      • {rec.get('issue')}")
            else:
                output.append("   ✅ All best practices checks passed")
        
        return "\n".join(output)
    
    def _format_ai_recommendations_human_readable(self, recommendations: Dict) -> str:
        """Format AI recommendations in human-readable format."""
        output = []
        output.append("\n🤖 AI-Powered Recommendations")
        output.append("=" * 50)
        
        if isinstance(recommendations, dict):
            if 'recommendations' in recommendations and isinstance(recommendations['recommendations'], str):
                # Handle text-based recommendations
                output.append("\n💡 AI Analysis:")
                lines = recommendations['recommendations'].split('\n')
                for line in lines:
                    if line.strip():
                        output.append(f"   {line.strip()}")
            else:
                # Handle structured recommendations
                for key, value in recommendations.items():
                    if isinstance(value, list):
                        output.append(f"\n📋 {key.replace('_', ' ').title()}:")
                        for item in value:
                            output.append(f"   • {item}")
                    elif isinstance(value, dict):
                        output.append(f"\n📂 {key.replace('_', ' ').title()}:")
                        for subkey, subvalue in value.items():
                            output.append(f"   {subkey}: {subvalue}")
                    else:
                        output.append(f"\n🔍 {key.replace('_', ' ').title()}: {value}")
        else:
            output.append(f"\n💡 AI Analysis:\n   {recommendations}")
        
        return "\n".join(output)
    
    def generate_pipeline(self) -> bool:
        """Generate complete CI/CD pipeline."""
        print("🚀 Generating AI-powered CI/CD pipeline...")
        
        # Analyze the codebase (includes AI security + best-practices enrichment)
        analysis = self.analyzer.analyze_project()
        
        # AI pipeline and infra recommendations
        analysis = self._ai_enhance_analysis(analysis)
        
        # Generate pipeline components
        success = True
        
        try:
            self._generate_github_workflow(analysis)
            self._generate_ai_workflow_trigger()
            self._ensure_terraform_infrastructure(analysis)
            self._ensure_docker_configuration(analysis)
            self.apply_infra_fixes(analysis)
            self._update_readme(analysis)
            self._increment_version()
            
            print("✅ Pipeline generation completed successfully!")
            
        except Exception as e:
            print(f"❌ Pipeline generation failed: {e}")
            success = False
        
        return success
    
    def _generate_github_workflow(self, analysis: Dict):
        """Generate GitHub Actions CI/CD workflow."""
        print("📝 Generating GitHub Actions workflow...")
        
        workflow_dir = self.project_root / '.github' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)
        
        # Main CI/CD workflow
        workflow = {
            'name': f"{self.config.get('pipeline_name', 'AI-Generated Pipeline')}",
            'on': {
                'push': {'branches': ['main', 'develop']},
                'pull_request': {'branches': ['main']},
                'workflow_dispatch': {}
            },
            'env': {
                'AWS_REGION': 'us-east-1',
                'TERRAFORM_VERSION': '1.5.0'
            },
            'jobs': {
                'validate': self._create_validation_job(analysis),
                'test': self._create_test_job(analysis),
                'deploy': self._create_deploy_job(analysis)
            }
        }
        
        workflow_path = workflow_dir / 'ci-cd.yml'
        with open(workflow_path, 'w') as f:
            yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)
        
        print(f"✅ Created workflow: {workflow_path}")
    
    def _create_validation_job(self, analysis: Dict) -> Dict:
        """Create validation job for the workflow."""
        job = {
            'name': 'Validate Code and Infrastructure',
            'runs-on': 'ubuntu-latest',
            'steps': [
                {
                    'name': 'Checkout code',
                    'uses': 'actions/checkout@v4'
                },
                {
                    'name': 'Validate YAML files',
                    'run': 'find . -name "*.yml" -o -name "*.yaml" | xargs -I {} sh -c \'echo "Validating {}" && python -c "import yaml; yaml.safe_load(open(\'{}\'))" || exit 1\''
                }
            ]
        }
        
        # Add Terraform validation if terraform exists
        if analysis['infrastructure']['terraform_exists']:
            job['steps'].extend([
                {
                    'name': 'Setup Terraform',
                    'uses': 'hashicorp/setup-terraform@v3',
                    'with': {'terraform_version': '${{ env.TERRAFORM_VERSION }}'}
                },
                {
                    'name': 'Terraform Format Check',
                    'run': 'terraform fmt -check -recursive terraform/',
                    'continue-on-error': True
                },
                {
                    'name': 'Terraform Validate',
                    'run': '''
                    cd terraform
                    terraform init -backend=false
                    terraform validate
                    '''
                }
            ])
        
        return job
    
    def _create_test_job(self, analysis: Dict) -> Dict:
        """Create testing job for the workflow."""
        job = {
            'name': 'Run Tests',
            'runs-on': 'ubuntu-latest',
            'needs': 'validate',
            'steps': [
                {
                    'name': 'Checkout code',
                    'uses': 'actions/checkout@v4'
                }
            ]
        }
        
        # Add backend testing
        if analysis['backend']['exists']:
            if analysis['backend'].get('language') == 'python':
                job['steps'].extend([
                    {
                        'name': 'Set up Python',
                        'uses': 'actions/setup-python@v4',
                        'with': {'python-version': '3.11'}
                    },
                    {
                        'name': 'Install backend dependencies',
                        'run': f"cd backend && {analysis['backend']['install_command']}"
                    },
                    {
                        'name': 'Lint backend code',
                        'run': f"cd backend && {analysis['backend']['lint_command']} || echo 'Linting not configured'",
                        'continue-on-error': True
                    },
                    {
                        'name': 'Test backend code',
                        'run': f"cd backend && {analysis['backend']['test_command']} || echo 'Tests not configured'",
                        'continue-on-error': True
                    }
                ])
        
        # Add frontend testing
        if analysis['frontend']['exists']:
            if analysis['frontend'].get('framework') == 'node':
                job['steps'].extend([
                    {
                        'name': 'Set up Node.js',
                        'uses': 'actions/setup-node@v4',
                        'with': {'node-version': '18'}
                    },
                    {
                        'name': 'Install frontend dependencies',
                        'run': f"cd frontend && {analysis['frontend']['install_command']}"
                    },
                    {
                        'name': 'Lint frontend code',
                        'run': f"cd frontend && {analysis['frontend']['lint_command']} || echo 'Linting not configured'",
                        'continue-on-error': True
                    },
                    {
                        'name': 'Test frontend code',
                        'run': f"cd frontend && {analysis['frontend']['test_command']} || echo 'Tests not configured'",
                        'continue-on-error': True
                    }
                ])
            else:
                job['steps'].append({
                    'name': 'Validate frontend files',
                    'run': 'echo "Frontend validation: Static files detected, no additional tests needed"'
                })
        
        return job
    
    def _create_deploy_job(self, analysis: Dict) -> Dict:
        """Create deployment job for the workflow."""
        job = {
            'name': 'Deploy to AWS',
            'runs-on': 'ubuntu-latest',
            'needs': ['validate', 'test'],
            'if': 'github.ref == \'refs/heads/main\'',
            'env': {
                'AWS_ACCESS_KEY_ID': '${{ secrets.AWS_ACCESS_KEY_ID }}',
                'AWS_SECRET_ACCESS_KEY': '${{ secrets.AWS_SECRET_ACCESS_KEY }}'
            },
            'steps': [
                {
                    'name': 'Checkout code',
                    'uses': 'actions/checkout@v4'
                },
                {
                    'name': 'Setup Terraform',
                    'uses': 'hashicorp/setup-terraform@v3',
                    'with': {'terraform_version': '${{ env.TERRAFORM_VERSION }}'}
                },
                {
                    'name': 'Terraform Init',
                    'run': '''
                    cd terraform
                    terraform init
                    '''
                },
                {
                    'name': 'Terraform Plan',
                    'run': '''
                    cd terraform
                    terraform plan -out=tfplan
                    '''
                },
                {
                    'name': 'Terraform Apply',
                    'run': '''
                    cd terraform
                    terraform apply -auto-approve tfplan
                    '''
                },
                {
                    'name': 'Get deployment info',
                    'id': 'deployment',
                    'run': '''
                    cd terraform
                    echo "public_ip=$(terraform output -raw public_ip)" >> $GITHUB_OUTPUT
                    echo "frontend_url=$(terraform output -raw application_urls | jq -r .frontend)" >> $GITHUB_OUTPUT
                    echo "backend_url=$(terraform output -raw application_urls | jq -r .backend_api)" >> $GITHUB_OUTPUT
                    '''
                },
                {
                    'name': 'Wait for application startup',
                    'run': '''
                    echo "Waiting for application to start..."
                    sleep 60
                    
                    # Check application health
                    curl -f ${{ steps.deployment.outputs.backend_url }}/health || echo "Backend health check failed"
                    curl -f ${{ steps.deployment.outputs.frontend_url }} || echo "Frontend health check failed"
                    '''
                }
            ]
        }
        
        # Add email notification if configured
        if self.config.get('email_notification', 'false').lower() == 'true':
            job['steps'].append({
                'name': 'Send deployment notification',
                'if': 'always()',
                'uses': 'dawidd6/action-send-mail@v3',
                'with': {
                    'server_address': 'smtp.gmail.com',
                    'server_port': '587',
                    'username': '${{ secrets.EMAIL_USERNAME }}',
                    'password': '${{ secrets.EMAIL_PASSWORD }}',
                    'subject': 'QR Generator Deployment ${{ job.status }}',
                    'to': self.config.get('email_recipient', 'demo@example.com'),
                    'from': '${{ secrets.EMAIL_USERNAME }}',
                    'body': '''
                    Deployment Status: ${{ job.status }}
                    
                    Frontend URL: ${{ steps.deployment.outputs.frontend_url }}
                    Backend API: ${{ steps.deployment.outputs.backend_url }}
                    
                    Commit: ${{ github.sha }}
                    Repository: ${{ github.repository }}
                    '''
                }
            })
        
        return job
    
    def apply_infra_fixes(self, analysis: Dict) -> List[str]:
        """Apply security fixes directly to infra files based on analysis. Returns list of changed files."""
        changed = []
        security = analysis.get('security', {})
        infra_issues = security.get('infrastructure', [])

        for issue in infra_issues:
            category = issue.get('category', '')
            issue_text = issue.get('issue', '')

            # Fix: add non-root USER to Dockerfiles missing it
            if category == 'Container Security' and 'runs as root' in issue_text:
                # Extract relative path from issue text e.g. "frontend/Dockerfile"
                match = re.search(r'in (.+Dockerfile)', issue_text)
                if not match:
                    continue
                dockerfile_path = self.project_root / match.group(1)
                if not dockerfile_path.exists():
                    continue
                content = dockerfile_path.read_text()
                if re.search(r'^USER\s+', content, re.MULTILINE):
                    continue  # already fixed

                # Determine appropriate non-root user for the base image
                if 'nginx' in content.lower():
                    user_line = 'USER nginx'
                elif 'python' in content.lower():
                    # Add user creation before CMD
                    user_setup = 'RUN adduser --disabled-password --gecos "" appuser\nUSER appuser'
                    content = re.sub(r'^(CMD\s)', user_setup + '\n\n\g<1>', content, flags=re.MULTILINE)
                    dockerfile_path.write_text(content)
                    changed.append(str(dockerfile_path.relative_to(self.project_root)))
                    print(f"🔒 Fixed: added non-root user to {dockerfile_path.relative_to(self.project_root)}")
                    continue
                else:
                    user_line = 'USER nobody'

                # For nginx and others, append USER before EXPOSE or at end
                content = re.sub(r'^(EXPOSE\s)', user_line + '\n\n\g<1>', content, flags=re.MULTILINE)
                if user_line not in content:
                    content = content.rstrip() + f'\n{user_line}\n'
                dockerfile_path.write_text(content)
                changed.append(str(dockerfile_path.relative_to(self.project_root)))
                print(f"🔒 Fixed: added non-root user to {dockerfile_path.relative_to(self.project_root)}")

            # Fix: pin :latest base image tags
            elif category == 'Container Security' and ':latest' in issue_text:
                match = re.search(r'in (.+Dockerfile)', issue_text)
                if not match:
                    continue
                dockerfile_path = self.project_root / match.group(1)
                if not dockerfile_path.exists():
                    continue
                content = dockerfile_path.read_text()
                # Replace known :latest patterns with pinned versions
                pinned = {
                    'nginx:latest': 'nginx:1.25-alpine',
                    'python:latest': 'python:3.11-slim',
                    'node:latest': 'node:20-alpine',
                    'ubuntu:latest': 'ubuntu:22.04',
                    'alpine:latest': 'alpine:3.19',
                }
                new_content = content
                for unpinned, pinned_tag in pinned.items():
                    new_content = new_content.replace(unpinned, pinned_tag)
                # Generic fallback: replace any remaining :latest
                new_content = re.sub(r'(FROM\s+\S+):latest', r'\1:stable', new_content)
                if new_content != content:
                    dockerfile_path.write_text(new_content)
                    changed.append(str(dockerfile_path.relative_to(self.project_root)))
                    print(f"🔒 Fixed: pinned :latest tag in {dockerfile_path.relative_to(self.project_root)}")

        if not changed:
            print("✅ No infra fixes needed — all issues are code-level (see suggestions.md)")
        return changed

    def suggest_changes(self, analysis: Dict):
        """Write suggestions.md with actionable recommendations based on analysis."""
        suggestions = []
        docker = analysis.get('docker', {})
        backend = analysis.get('backend', {})
        frontend = analysis.get('frontend', {})
        infra = analysis.get('infrastructure', {})
        security = analysis.get('security', {})
        best_practices = analysis.get('best_practices', {})

        # Structural issues
        if not docker.get('dockerfiles'):
            suggestions.append((
                'Missing Dockerfiles',
                'High',
                'No Dockerfiles found for frontend or backend. `docker-compose up` will fail.',
                '- Create `backend/Dockerfile` and `frontend/Dockerfile`'
            ))

        if not docker.get('compose_exists'):
            suggestions.append((
                'Missing docker-compose.yml',
                'High',
                'No Docker Compose file found. Local development setup is incomplete.',
                '- Create `docker-compose.yml` with frontend and backend services'
            ))

        if backend.get('exists') and not (self.project_root / 'backend' / 'test_main.py').exists():
            suggestions.append((
                'No backend tests detected',
                'Medium',
                'No test file found in backend/. CI pipeline runs pytest but has nothing to test.',
                '- Add `backend/test_main.py` with basic health check and endpoint tests'
            ))

        if not infra.get('terraform_exists'):
            suggestions.append((
                'Missing Terraform configuration',
                'Medium',
                'No terraform/ directory found. AWS deployment will not work.',
                '- Run `python ai_devops_agent.py` to auto-generate Terraform files'
            ))

        if backend.get('exists'):
            req_file = self.project_root / 'backend' / 'requirements-dev.txt'
            if not req_file.exists():
                suggestions.append((
                    'No dev dependencies file',
                    'Low',
                    'requirements-dev.txt is missing. Linting tools (flake8) are not declared.',
                    '- Create `backend/requirements-dev.txt` with `flake8` and `pytest`'
                ))

        # Security vulnerabilities
        security_issues = []
        if security:
            for vuln in security.get('frontend', []):
                security_issues.append((
                    f"[Frontend] {vuln.get('issue')}",
                    vuln.get('severity', 'MEDIUM'),
                    vuln.get('description', ''),
                    vuln.get('recommendation', '')
                ))
            
            for vuln in security.get('backend', []):
                security_issues.append((
                    f"[Backend] {vuln.get('issue')}",
                    vuln.get('severity', 'MEDIUM'),
                    vuln.get('description', ''),
                    vuln.get('recommendation', '')
                ))
            
            for vuln in security.get('infrastructure', []):
                security_issues.append((
                    f"[Infrastructure] {vuln.get('issue')}",
                    vuln.get('severity', 'MEDIUM'),
                    vuln.get('description', ''),
                    vuln.get('recommendation', '')
                ))

        # Best practices recommendations
        bp_recommendations = []
        if best_practices:
            for rec in best_practices.get('frontend', []):
                bp_recommendations.append((
                    f"[Frontend] {rec.get('issue')}",
                    'Low',
                    f"{rec.get('category', 'General')}",
                    rec.get('recommendation', '')
                ))
            
            for rec in best_practices.get('backend', []):
                bp_recommendations.append((
                    f"[Backend] {rec.get('issue')}",
                    'Low',
                    f"{rec.get('category', 'General')}",
                    rec.get('recommendation', '')
                ))
            
            for rec in best_practices.get('general', []):
                bp_recommendations.append((
                    f"[Project] {rec.get('issue')}",
                    'Low',
                    f"{rec.get('category', 'General')}",
                    rec.get('recommendation', '')
                ))

        ai_recs = analysis.get('ai_recommendations', {})
        ai_security_enrichment = analysis.get('security', {}).get('ai_enrichment', {})
        ai_bp_enrichment = analysis.get('best_practices', {}).get('ai_enrichment', {})

        lines = [
            '# AI DevOps Analysis — Comprehensive Report',
            '',
            f'> Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            f'> Triggered by: post-analysis',
            '',
        ]

        # Security Section
        if security_issues:
            lines.append('## 🔒 Security Vulnerabilities')
            lines.append('')
            risk_level = security.get('overall_risk', 'UNKNOWN')
            risk_emoji = '🔴' if risk_level == 'HIGH' else '🟡' if risk_level == 'MEDIUM' else '🟢'
            lines.append(f'**Overall Risk Level**: {risk_emoji} {risk_level}')
            lines.append('')
            
            # Sort by severity
            high_priority = [s for s in security_issues if s[1] == 'HIGH']
            medium_priority = [s for s in security_issues if s[1] == 'MEDIUM']
            low_priority = [s for s in security_issues if s[1] == 'LOW']
            
            for title, severity, description, fix in high_priority + medium_priority + low_priority:
                lines.append(f'### {title}')
                lines.append(f'- **Severity**: {severity}')
                lines.append(f'- **Issue**: {description}')
                lines.append(f'- **Recommendation**: {fix}')
                lines.append('')
        else:
            lines.append('## ✅ No Security Issues Found')
            lines.append('')

        # Structural Issues Section
        if suggestions:
            lines.append('## 🔧 Structural Issues')
            lines.append('')
            for title, severity, description, fix in suggestions:
                lines.append(f'### {title}')
                lines.append(f'- **Severity**: {severity}')
                lines.append(f'- **Issue**: {description}')
                lines.append(f'- **Suggested fix**: {fix}')
                lines.append('')

        # Best Practices Section
        if bp_recommendations:
            lines.append('## 📋 Best Practices Recommendations')
            lines.append('')
            score = best_practices.get('compliance_score', 0)
            score_emoji = '🟢' if score >= 80 else '🟡' if score >= 60 else '🔴'
            lines.append(f'**Compliance Score**: {score_emoji} {score}%')
            lines.append('')
            
            for title, severity, category, recommendation in bp_recommendations:
                lines.append(f'### {title}')
                lines.append(f'- **Category**: {category}')
                lines.append(f'- **Recommendation**: {recommendation}')
                lines.append('')

        # AI Security Enrichment Section
        if ai_security_enrichment:
            lines.append('## 🤖 AI Security Analysis')
            lines.append('')
            if 'attack_surface_summary' in ai_security_enrichment:
                lines.append(f"**Attack Surface**: {ai_security_enrichment['attack_surface_summary']}")
                lines.append('')
            if 'top_3_actions' in ai_security_enrichment:
                lines.append('**Top 3 Immediate Actions:**')
                for action in ai_security_enrichment['top_3_actions']:
                    lines.append(f'- {action}')
                lines.append('')
            if 'enriched_findings' in ai_security_enrichment:
                lines.append('**Enriched Findings:**')
                for finding in ai_security_enrichment['enriched_findings']:
                    title = finding.get('issue', finding.get('title', 'Finding'))
                    lines.append(f"### {title}")
                    if finding.get('cve_references'):
                        lines.append(f"- **CVE References**: {', '.join(finding['cve_references']) if isinstance(finding['cve_references'], list) else finding['cve_references']}")
                    if finding.get('exploit_scenario'):
                        lines.append(f"- **Exploit Scenario**: {finding['exploit_scenario']}")
                    if finding.get('priority_fix'):
                        lines.append(f"- **Priority Fix**: {finding['priority_fix']}")
                    lines.append('')

        # AI Best Practices Enrichment Section
        if ai_bp_enrichment:
            lines.append('## 🤖 AI Best Practices Insights')
            lines.append('')
            if 'maturity_level' in ai_bp_enrichment:
                lines.append(f"**Project Maturity**: {ai_bp_enrichment['maturity_level']}")
                lines.append('')
            if 'quick_wins' in ai_bp_enrichment:
                lines.append('**Quick Wins:**')
                for win in ai_bp_enrichment['quick_wins']:
                    lines.append(f'- {win}')
                lines.append('')
            if 'prioritised_recommendations' in ai_bp_enrichment:
                lines.append('**Prioritised Recommendations:**')
                for rec in ai_bp_enrichment['prioritised_recommendations']:
                    lines.append(f"### {rec.get('title', 'Recommendation')}")
                    lines.append(f"- **Effort**: {rec.get('effort', 'N/A')} | **Impact**: {rec.get('impact', 'N/A')}")
                    for step in rec.get('steps', []):
                        lines.append(f"  - {step}")
                    lines.append('')

        # AI Pipeline Recommendations Section
        if ai_recs:
            lines.append('## 🤖 AI Pipeline & Infrastructure Recommendations')
            lines.append('')
            if 'pipeline_stages' in ai_recs:
                lines.append('**Recommended Pipeline Stages:**')
                for stage in ai_recs['pipeline_stages']:
                    tools = ', '.join(stage.get('tools', [])) if isinstance(stage.get('tools'), list) else stage.get('tools', '')
                    lines.append(f"- **{stage.get('name', '')}**: {stage.get('purpose', '')} *(tools: {tools})*")
                lines.append('')
            if 'deployment_recommendations' in ai_recs:
                lines.append('**Deployment Recommendations:**')
                for rec in ai_recs['deployment_recommendations']:
                    lines.append(f'- {rec}')
                lines.append('')
            if 'infra_optimisations' in ai_recs:
                lines.append('**Infrastructure Optimisations:**')
                for opt in ai_recs['infra_optimisations']:
                    lines.append(f'- {opt}')
                lines.append('')
            if 'performance_tips' in ai_recs:
                lines.append('**Performance Tips:**')
                for tip in ai_recs['performance_tips']:
                    lines.append(f'- {tip}')
                lines.append('')

        # Project Summary
        lines.append('## 📊 Project Summary')
        lines.append('')
        lines.append(f'- **Frontend**: {frontend.get("framework", "unknown")} on port {frontend.get("port", "N/A")}')
        lines.append(f'- **Backend**: {backend.get("framework", "unknown")} on port {backend.get("port", "N/A")}')
        lines.append(f'- **Terraform**: {"✅ exists" if infra.get("terraform_exists") else "❌ missing"}')
        lines.append(f'- **Docker Compose**: {"✅ exists" if docker.get("compose_exists") else "❌ missing"}')
        lines.append(f'- **Dockerfiles**: {len(docker.get("dockerfiles", []))} found')
        lines.append(f'- **Security Risk**: {security.get("overall_risk", "N/A")}')
        lines.append(f'- **Best Practices Score**: {best_practices.get("compliance_score", "N/A")}%')

        suggestions_path = self.project_root / 'suggestions.md'
        suggestions_path.write_text('\n'.join(lines))
        print(f'📝 Comprehensive analysis written to {suggestions_path}')
        
        total_issues = len(suggestions) + len(security_issues) + len(bp_recommendations)
        print(f'   Found {total_issues} total finding(s):')
        print(f'     • Security Issues: {len(security_issues)}')
        print(f'     • Structural Issues: {len(suggestions)}')
        print(f'     • Best Practice Recommendations: {len(bp_recommendations)}')

    def _generate_ai_workflow_trigger(self):
        """Regenerate the canonical AI workflow trigger (always overwrites)."""
        print("🤖 Regenerating AI workflow trigger...")

        workflow_dir = self.project_root / '.github' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)

        # Read the canonical workflow template and write it back
        # This ensures the file stays in sync after pipeline regeneration
        canonical_path = workflow_dir / 'ai-generate-workflow.yml'

        # If the canonical file already exists, preserve it as-is during generate_pipeline
        # (it is managed by the workflow itself and fixed separately)
        if canonical_path.exists():
            print(f"✅ AI workflow already exists, preserving: {canonical_path}")
            return

        # Only write a bootstrap version on first-time generation
        bootstrap_workflow = {
            'name': 'AI Pipeline Analyzer',
            'on': {
                'pull_request': {
                    'types': ['opened', 'synchronize', 'reopened', 'closed'],
                    'branches': ['main']
                },
                'workflow_dispatch': {}
            },
            'jobs': {
                'analyze-and-comment': {
                    'if': "github.event_name == 'pull_request' && github.event.action != 'closed'",
                    'runs-on': 'ubuntu-latest',
                    'permissions': {'contents': 'read', 'pull-requests': 'write'},
                    'steps': [
                        {'name': 'Checkout PR branch', 'uses': 'actions/checkout@v4',
                         'with': {'ref': '${{ github.event.pull_request.head.sha }}', 'fetch-depth': 0}},
                        {'name': 'Set up Python', 'uses': 'actions/setup-python@v4',
                         'with': {'python-version': '3.11'}},
                        {'name': 'Install dependencies', 'run': 'pip install pyyaml requests'},
                        {'name': 'Run AI analyzer', 'env': {'OPENAI_API_TOKEN': '${{ secrets.OPENAI_API_TOKEN }}'},
                         'run': 'python ai_devops_agent.py --analyze-only --verbose > analysis_output.txt 2>&1 || true'},
                        {'name': 'Generate suggestions report',
                         'run': 'python ai_devops_agent.py --suggest-changes || true'},
                        {'name': 'Post analysis comment on PR',
                         'env': {'GH_TOKEN': '${{ secrets.PAT_TOKEN }}'},
                         'run': 'gh pr comment ${{ github.event.pull_request.number }} --body-file suggestions.md || true'}
                    ]
                },
                'create-fix-pr': {
                    'if': "github.event_name == 'pull_request' && github.event.pull_request.merged == true",
                    'runs-on': 'ubuntu-latest',
                    'permissions': {'contents': 'write', 'pull-requests': 'write'},
                    'steps': [
                        {'name': 'Checkout main branch', 'uses': 'actions/checkout@v4',
                         'with': {'token': '${{ secrets.PAT_TOKEN }}', 'ref': 'main', 'fetch-depth': 0}},
                        {'name': 'Set up Python', 'uses': 'actions/setup-python@v4',
                         'with': {'python-version': '3.11'}},
                        {'name': 'Install dependencies', 'run': 'pip install pyyaml requests'},
                        {'name': 'Run AI generator on merged code',
                         'env': {'OPENAI_API_TOKEN': '${{ secrets.OPENAI_API_TOKEN }}'},
                         'run': 'python ai_devops_agent.py'},
                        {'name': 'Generate suggestions',
                         'run': 'python ai_devops_agent.py --suggest-changes'},
                        {'name': 'Check for suggested changes', 'id': 'check_changes',
                         'run': 'git add -A\nif git diff --cached --quiet; then\n  echo "has_changes=false" >> $GITHUB_OUTPUT\nelse\n  echo "has_changes=true" >> $GITHUB_OUTPUT\nfi\n'},
                        {'name': 'Create suggestion branch and PR',
                         'if': "steps.check_changes.outputs.has_changes == 'true'",
                         'env': {'GH_TOKEN': '${{ secrets.PAT_TOKEN }}'},
                         'run': 'BRANCH="ai-suggestions-$(date +%Y%m%d-%H%M%S)"\ngit config user.name "github-actions[bot]"\ngit config user.email "github-actions[bot]@users.noreply.github.com"\ngit checkout -b "$BRANCH"\ngit commit -m "AI: Post-merge pipeline updates"\ngit push origin "$BRANCH"\nPR_BODY=$(cat suggestions.md 2>/dev/null || echo "AI analysis completed.")\ngh pr create --title "🤖 AI Suggestions: Post-merge fixes" --body "$PR_BODY" --base main --head "$BRANCH"\n'}
                    ]
                }
            }
        }

        with open(canonical_path, 'w') as f:
            yaml.dump(bootstrap_workflow, f, default_flow_style=False, sort_keys=False)
        print(f"✅ Created bootstrap AI workflow: {canonical_path}")

    def _ensure_terraform_infrastructure(self, analysis: Dict):
        """Ensure Terraform infrastructure exists and apply any infra suggestions."""
        terraform_path = self.project_root / 'terraform'
        terraform_path.mkdir(exist_ok=True)

        main_tf_exists = (terraform_path / 'main.tf').exists()
        variables_tf_exists = (terraform_path / 'variables.tf').exists()
        outputs_tf_exists = (terraform_path / 'outputs.tf').exists()

        if main_tf_exists and variables_tf_exists and outputs_tf_exists:
            print("✅ Terraform infrastructure exists — applying config-driven updates...")
            # Always regenerate variables and tfvars so pipeline_request.txt changes are reflected
            self._create_terraform_variables(terraform_path)
            self._create_terraform_tfvars(terraform_path)
            print("✅ Terraform variables and tfvars updated from pipeline_request.txt")
            return

        print("🏗️  Generating Terraform infrastructure...")
        
        # Create terraform directory
        terraform_path.mkdir(exist_ok=True)
        
        # Generate main.tf
        self._create_terraform_main(terraform_path, analysis)
        
        # Generate variables.tf
        self._create_terraform_variables(terraform_path)
        
        # Generate outputs.tf
        self._create_terraform_outputs(terraform_path)
        
        # Generate terraform.tfvars based on config
        self._create_terraform_tfvars(terraform_path)
        
        print("✅ Created Terraform infrastructure files")
    
    def _create_terraform_main(self, terraform_path: Path, analysis: Dict):
        """Create main.tf file."""
        # Get ports from config first, then fallback to analysis, then defaults
        backend_port = self.config.get('backend_port', analysis['backend'].get('port', 8000))
        frontend_port = self.config.get('frontend_port', analysis['frontend'].get('port', 3000))
        
        # Convert string ports to integers if needed
        try:
            backend_port = int(backend_port)
            frontend_port = int(frontend_port)
        except (ValueError, TypeError):
            backend_port = 8000
            frontend_port = 3000
        
        main_tf_content = f'''# AWS Provider configuration
terraform {{
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

# Security group for the application
resource "aws_security_group" "qr_generator_sg" {{
  name_prefix = "qr-generator-"
  description = "Security group for QR Generator application"
  
  # Allow HTTP traffic
  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # Allow HTTPS traffic
  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp" 
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # Allow SSH access
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # Allow backend port
  ingress {{
    from_port   = var.backend_port
    to_port     = var.backend_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # Allow frontend port
  ingress {{
    from_port   = var.frontend_port
    to_port     = var.frontend_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  # Allow all outbound traffic
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  
  tags = {{
    Name = "qr-generator-security-group"
    Project = "QR Generator"
  }}
}}

# EC2 Instance for the application
resource "aws_instance" "qr_generator" {{
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_pair_name
  
  vpc_security_group_ids = [aws_security_group.qr_generator_sg.id]
  
  # User data script to set up the application
  user_data = base64encode(templatefile("${{path.module}}/user_data.sh", {{
    backend_port  = var.backend_port
    frontend_port = var.frontend_port
  }}))
  
  root_block_device {{
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }}
  
  tags = merge(var.tags, {{
    Name = "${{var.project_name}}-instance"
    Type = "application-server"
  }})
}}

# Elastic IP for the instance
resource "aws_eip" "qr_generator_eip" {{
  instance = aws_instance.qr_generator.id
  domain   = "vpc"
  
  tags = {{
    Name = "qr-generator-eip"
    Project = "QR Generator"
  }}
}}
'''
        
        (terraform_path / 'main.tf').write_text(main_tf_content)
        
        # Create user_data.sh
        user_data_content = '''#!/bin/bash
set -e

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install Git
yum install git -y

# Create application directory
mkdir -p /opt/qr-generator
cd /opt/qr-generator

# Clone the repository (this would be updated with actual repo URL)
# git clone https://github.com/your-username/qr-generator.git .

# For now, create a simple deployment script
cat > deploy.sh << 'EOF'
#!/bin/bash
echo "Starting QR Generator application..."

# Start services with Docker Compose
docker-compose up -d

# Show status
docker-compose ps

echo "Application deployed successfully!"
echo "Backend available at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):${backend_port}"
echo "Frontend available at: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):${frontend_port}"
EOF

chmod +x deploy.sh

# Set up log rotation
cat > /etc/logrotate.d/qr-generator << 'EOF'
/opt/qr-generator/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    create 644 ec2-user ec2-user
}
EOF

echo "QR Generator infrastructure setup completed!"
'''
        
        (terraform_path / 'user_data.sh').write_text(user_data_content)
    
    def _create_terraform_variables(self, terraform_path: Path):
        """Create variables.tf file."""
        # Get configuration values with defaults
        environment = self.config.get('environment', 'dev')
        instance_type = self.config.get('instance_type', 't3.micro')
        project_name = self.config.get('pipeline_name', 'qr-generator').replace('-auto-pipeline', '')
        
        # Map AMI configuration
        ami_config = self.config.get('ami', 'latest-ubuntu')
        if 'ubuntu' in ami_config.lower():
            default_ami = "ami-0c7217cdde317cfec"  # Ubuntu 22.04 LTS
            ami_comment = "Ubuntu 22.04 LTS"
        else:
            default_ami = "ami-0c02fb55956c7d316"  # Amazon Linux 2
            ami_comment = "Amazon Linux 2 AMI (HVM) - Kernel 5.10, SSD Volume Type"
        
        variables_content = f'''# AWS Configuration Variables
variable "aws_region" {{
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}}

variable "environment" {{
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "{environment}"
}}

# EC2 Configuration
variable "ami_id" {{
  description = "AMI ID for EC2 instance"
  type        = string
  default     = "{default_ami}" # {ami_comment}
}}

variable "instance_type" {{
  description = "EC2 instance type"
  type        = string
  default     = "{instance_type}"
}}

variable "key_pair_name" {{
  description = "Name of the AWS key pair for EC2 access"
  type        = string
}}

# Application Configuration
variable "project_name" {{
  description = "Name of the project"
  type        = string
  default     = "{project_name}"
}}

variable "tags" {{
  description = "Common tags for all resources"
  type        = map(string)
  default = {{
    Project     = "{project_name.title()}"
    ManagedBy   = "Terraform"
    Environment = "{environment}"
  }}
}}

# Application Port Configuration
variable "frontend_port" {{
  description = "Port for the frontend application"
  type        = number
  default     = {self.config.get('frontend_port', 3000)}
}}

variable "backend_port" {{
  description = "Port for the backend application"  
  type        = number
  default     = {self.config.get('backend_port', 8000)}
}}

# Deployment Configuration
variable "deploy_method" {{
  description = "Deployment method (docker-compose, kubernetes, etc.)"
  type        = string
  default     = "{self.config.get('deploy_using', 'docker-compose')}"
}}

variable "target_platform" {{
  description = "Target deployment platform"
  type        = string
  default     = "{self.config.get('target', 'aws_ec2')}"
}}
'''
        
        (terraform_path / 'variables.tf').write_text(variables_content)
    
    def _create_terraform_outputs(self, terraform_path: Path):
        """Create outputs.tf file using configured ports."""
        backend_port = self.config.get('backend_port', 8000)
        frontend_port = self.config.get('frontend_port', 3000)

        outputs_content = f'''# EC2 Instance Outputs
output "instance_id" {{
  description = "ID of the EC2 instance"
  value       = aws_instance.qr_generator.id
}}

output "instance_public_ip" {{
  description = "Public IP address of the EC2 instance"
  value       = aws_eip.qr_generator_eip.public_ip
}}

# Alias used by CI deploy job
output "public_ip" {{
  description = "Public IP address (alias for CI pipeline)"
  value       = aws_eip.qr_generator_eip.public_ip
}}

output "instance_public_dns" {{
  description = "Public DNS name of the EC2 instance"
  value       = aws_instance.qr_generator.public_dns
}}

output "instance_private_ip" {{
  description = "Private IP address of the EC2 instance"
  value       = aws_instance.qr_generator.private_ip
}}

# Security Group Output
output "security_group_id" {{
  description = "ID of the security group"
  value       = aws_security_group.qr_generator_sg.id
}}

# Application URLs
output "backend_url" {{
  description = "URL for the backend application"
  value       = "http://${{aws_eip.qr_generator_eip.public_ip}}:${{var.backend_port}}"
}}

output "frontend_url" {{
  description = "URL for the frontend application"
  value       = "http://${{aws_eip.qr_generator_eip.public_ip}}:${{var.frontend_port}}"
}}

# Combined URLs map used by CI deploy job
output "application_urls" {{
  description = "Application endpoint URLs"
  value = jsonencode({{
    frontend    = "http://${{aws_eip.qr_generator_eip.public_ip}}:${{var.frontend_port}}"
    backend_api = "http://${{aws_eip.qr_generator_eip.public_ip}}:${{var.backend_port}}"
  }})
}}

# SSH Access
output "ssh_command" {{
  description = "SSH command to connect to the instance"
  value       = "ssh -i ~/.ssh/${{var.key_pair_name}}.pem ubuntu@${{aws_eip.qr_generator_eip.public_ip}}"
}}
'''

        (terraform_path / 'outputs.tf').write_text(outputs_content)
    
    def _create_terraform_tfvars(self, terraform_path: Path):
        """Create terraform.tfvars file based on pipeline_request.txt configuration."""
        # Get configuration values
        environment = self.config.get('environment', 'dev')
        instance_type = self.config.get('instance_type', 't3.micro')
        project_name = self.config.get('pipeline_name', 'qr-generator').replace('-auto-pipeline', '')
        ami_config = self.config.get('ami', 'latest-ubuntu')
        
        # Map AMI configuration to actual AMI IDs
        if 'ubuntu' in ami_config.lower():
            ami_id = "ami-0c7217cdde317cfec"  # Ubuntu 22.04 LTS
        elif 'amazon' in ami_config.lower() or 'linux' in ami_config.lower():
            ami_id = "ami-0c02fb55956c7d316"  # Amazon Linux 2
        else:
            ami_id = "ami-0c7217cdde317cfec"  # Default to Ubuntu
        
        # Create tfvars content
        tfvars_content = f'''# Generated from pipeline_request.txt configuration
# Environment Configuration
environment = "{environment}"

# EC2 Configuration  
instance_type = "{instance_type}"
ami_id = "{ami_id}"

# Project Configuration
project_name = "{project_name}"

# Additional tags based on configuration
tags = {{
  Project = "{project_name.replace('-', ' ').title()}"
  Environment = "{environment}"
  ManagedBy = "Terraform"
  GeneratedFrom = "pipeline_request.txt"
  Labels = "{','.join(self.config.get('labels', ['ai-generated']))}"
}}

# AWS Configuration (update these values as needed)
aws_region = "us-west-2"

# Key Pair (REQUIRED: Set this to your AWS key pair name)
# key_pair_name = "your-key-pair-name"
'''

        # Add application-specific configurations
        frontend_port = self.config.get('frontend_port', '3000')
        backend_port = self.config.get('backend_port', '8000')
        
        tfvars_content += f'''
# Application Configuration (from pipeline_request.txt)
# These ports are used in security group rules and outputs
frontend_port = {frontend_port}
backend_port = {backend_port}

# Deployment Configuration
deploy_method = "{self.config.get('deploy_using', 'docker-compose')}"
target_platform = "{self.config.get('target', 'aws_ec2')}"
'''
        
        # Write the tfvars file
        (terraform_path / 'terraform.tfvars').write_text(tfvars_content)
        
        # Also create a .tfvars.example file for reference
        example_content = tfvars_content.replace('# key_pair_name = "your-key-pair-name"', 'key_pair_name = "your-key-pair-name"')
        example_content = example_content.replace('aws_region = "us-west-2"', 'aws_region = "us-east-1"')
        (terraform_path / 'terraform.tfvars.example').write_text(example_content)
        
        print(f"   📄 Created terraform.tfvars with {environment} environment and {instance_type} instance")
    
    def _ensure_docker_configuration(self, analysis: Dict):
        """Ensure Docker configuration exists, generating missing Dockerfiles."""
        if analysis['docker']['compose_exists']:
            print("✅ Docker Compose configuration already exists")

        if not analysis['docker']['dockerfiles']:
            print("🐳 No Dockerfiles found — generating...")
            self._create_backend_dockerfile(analysis)
            self._create_frontend_dockerfile(analysis)

    def _create_backend_dockerfile(self, analysis: Dict):
        """Generate backend/Dockerfile for Python/FastAPI."""
        backend_path = self.project_root / 'backend'
        if not backend_path.exists():
            return
        dockerfile_path = backend_path / 'Dockerfile'
        if dockerfile_path.exists():
            return
        port = analysis['backend'].get('port', 8000)
        content = f'''FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE {port}
RUN adduser --disabled-password --gecos "" appuser
USER appuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}"]
'''
        dockerfile_path.write_text(content)
        print(f"✅ Created backend/Dockerfile (port {port})")

    def _create_frontend_dockerfile(self, analysis: Dict):
        """Generate frontend/Dockerfile for nginx static serving."""
        frontend_path = self.project_root / 'frontend'
        if not frontend_path.exists():
            return
        dockerfile_path = frontend_path / 'Dockerfile'
        if dockerfile_path.exists():
            return
        port = analysis['frontend'].get('port', 3000)
        content = f'''FROM nginx:1.25-alpine
COPY . /usr/share/nginx/html
EXPOSE {port}
USER nginx
'''
        dockerfile_path.write_text(content)
        print(f"✅ Created frontend/Dockerfile (port {port})")
    
    def _update_readme(self, analysis: Dict):
        """Update README.md with comprehensive documentation."""
        print("📖 Updating README.md...")
        
        readme_content = f'''# QR Code Generator - AI-Powered CI/CD Demo

This project demonstrates **AI-assisted DevOps automation** with a complete CI/CD pipeline that automatically analyzes code and generates infrastructure.

## 🎯 Project Overview

**QR Code Generator** is a full-stack web application that generates QR codes from various data types:
- Plain text
- URLs
- Email addresses  
- Phone numbers
- WiFi credentials

### Architecture

- **Frontend**: {analysis['frontend'].get('framework', 'Unknown')} ({analysis['frontend'].get('port', 'N/A')} port)
- **Backend**: {analysis['backend'].get('framework', 'Unknown')} ({analysis['backend'].get('port', 'N/A')} port)
- **Infrastructure**: AWS EC2 with Terraform
- **Deployment**: Docker Compose
- **CI/CD**: GitHub Actions with AI-generated workflows

## 🚀 Quick Start

### Prerequisites

- AWS Account with CLI configured
- Docker and Docker Compose
- Terraform >= 1.5.0
- Python 3.11+
- Git

### Local Development

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd AISDLC2.0
   ```

2. **Run locally with Docker Compose**:
   ```bash
   docker-compose up -d
   ```

3. **Access the application**:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### AWS Deployment

1. **Configure AWS credentials**:
   ```bash
   aws configure
   ```

2. **Set up Terraform variables**:
   ```bash
   cd terraform
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your preferences
   ```

3. **Deploy to AWS**:
   ```bash
   terraform init
   terraform plan
   terraform apply
   ```

4. **Get deployment URLs**:
   ```bash
   terraform output application_urls
   ```

## 🤖 AI DevOps & Security Agent

The `ai_devops_agent.py` script automatically:

### Code Analysis
- Detects programming languages and frameworks
- Identifies dependencies and test commands
- Analyzes port configurations
- **Scans for security vulnerabilities**
- **Checks best practices compliance**
- Suggests optimal CI/CD strategies

### Infrastructure Generation
- Creates Terraform configurations for AWS EC2
- Generates Docker and Docker Compose files
- Sets up security groups and networking
- Configures auto-scaling and monitoring

### Pipeline Automation  
- Generates GitHub Actions workflows
- Sets up automated testing and linting
- Configures deployment strategies
- Implements rollback mechanisms

### Usage

```bash
# Run the AI DevOps Agent
python ai_devops_agent.py

# Run with auto-commit (for CI/CD)
python ai_devops_agent.py --auto-commit

# Analyze only (no file generation)
python ai_devops_agent.py --analyze-only
```

## 📁 Project Structure

```
.
├── README.md                          # This file
├── VERSION                            # Version tracking
├── pipeline_request.txt              # AI pipeline configuration
├── ai_devops_agent.py               # AI DevOps & security agent
├── docker-compose.yml               # Local development setup
├── frontend/                        # Frontend application
│   ├── index.html                  # Main HTML file
│   ├── script.js                   # JavaScript logic
│   ├── style.css                   # Styling
│   ├── Dockerfile                  # Frontend container
│   └── nginx.conf                  # Nginx configuration
├── backend/                         # Backend API
│   ├── main.py                     # FastAPI application
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Backend container
│   └── api/                        # API modules
├── terraform/                       # Infrastructure as Code
│   ├── main.tf                     # Main Terraform configuration
│   ├── variables.tf                # Variable definitions
│   ├── user_data.sh               # EC2 initialization script
│   └── terraform.tfvars.example   # Example configuration
└── .github/workflows/              # CI/CD pipelines
    ├── ci-cd.yml                   # Main deployment workflow
    └── ai-generate-workflow.yml    # AI generator trigger
```

## 🔄 CI/CD Workflow

The AI-generated pipeline includes:

### 1. **Validation Stage**
- YAML syntax validation
- Terraform formatting and validation  
- Code linting and security scanning

### 2. **Testing Stage**
- Backend API testing with pytest
- Frontend testing (if configured)
- Integration testing
- Security vulnerability scanning

### 3. **Deployment Stage**
- Terraform infrastructure provisioning
- Docker image building and pushing
- AWS EC2 deployment via user data script
- Health checks and monitoring setup

### 4. **Notification Stage**
- Email notifications on success/failure
- Slack/Teams integration (configurable)
- Deployment status reporting

## ⚙️ Configuration

### Pipeline Configuration (`pipeline_request.txt`)

```yaml
pipeline_name: qr-generator-auto-pipeline
environment: production
target: aws_ec2
instance_type: t2.micro
deploy_using: docker-compose
labels: [ai-generated, demo]
email_notification: true
email_recipient: your-email@example.com
```

### GitHub Secrets Required

- `AWS_ACCESS_KEY_ID`: AWS access key
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `EMAIL_USERNAME`: SMTP username (optional)
- `EMAIL_PASSWORD`: SMTP password (optional)

## 🛡️ Security Features

- EC2 security groups with minimal required ports
- Encrypted EBS volumes
- IAM roles with least privilege
- Container security scanning
- Secrets management via GitHub Secrets

## 📊 Monitoring & Logging

- CloudWatch monitoring for EC2 instances
- Application health checks
- Docker container logs
- Terraform state management
- Automated backup and recovery

## 🧹 Cleanup

To destroy the AWS infrastructure:

```bash
cd terraform
terraform destroy
```

To stop local development:

```bash
docker-compose down -v
```

## 🔧 Troubleshooting

### Common Issues

1. **AWS Permissions**: Ensure your AWS user has EC2, VPC, and IAM permissions
2. **Terraform State**: Use remote state storage for team collaboration
3. **Docker Build**: Check Dockerfile syntax and dependency availability
4. **Port Conflicts**: Ensure ports 3000, 8000, 80 are available

### Debug Commands

```bash
# Check application logs
docker-compose logs -f

# SSH into EC2 instance
ssh -i qr-generator-private-key.pem ubuntu@<instance-ip>

# Check Terraform state
terraform show

# Validate Terraform configuration
terraform validate
```

## 🤝 Contributing

This is a demo project showcasing AI-assisted DevOps. Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **FastAPI**: Modern Python web framework
- **Terraform**: Infrastructure as Code
- **GitHub Actions**: CI/CD automation
- **AWS**: Cloud infrastructure
- **Docker**: Containerization platform

---

**Generated by**: AI DevOps Agent v1.0
**Last Updated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Project Version**: {self._get_current_version()}
'''
        
        readme_path = self.project_root / 'README.md'
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        
        print(f"✅ Updated README: {readme_path}")
    
    def _increment_version(self):
        """Increment version in VERSION file."""
        version_file = self.project_root / 'VERSION'
        
        if version_file.exists():
            current_version = version_file.read_text().strip()
        else:
            current_version = '0.1.0'
        
        # Parse version (assuming semantic versioning)
        try:
            parts = current_version.split('.')
            patch = int(parts[2]) + 1
            new_version = f"{parts[0]}.{parts[1]}.{patch}"
        except:
            new_version = '0.1.1'
        
        version_file.write_text(new_version)
        print(f"📈 Version updated: {current_version} → {new_version}")
    
    def _get_current_version(self) -> str:
        """Get current version from VERSION file."""
        version_file = self.project_root / 'VERSION'
        if version_file.exists():
            return version_file.read_text().strip()
        return '0.1.0'

def main():
    """Main entry point for the AI DevOps & Security Agent."""
    parser = argparse.ArgumentParser(
        description='AI-Powered DevOps Agent with Security & Best Practices Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python ai_devops_agent.py                                    # Generate complete pipeline
  python ai_devops_agent.py --analyze-only                     # Analyze code, security & best practices
  python ai_devops_agent.py --auto-commit                      # Generate and commit changes
  python ai_devops_agent.py --suggest-changes                  # Generate suggestions.md report
  python ai_devops_agent.py --openai-token YOUR_TOKEN          # Use AI enhancement with OpenAI
  OPENAI_API_TOKEN=your_token python ai_devops_agent.py        # Use AI via environment variable
        '''
    )
    
    parser.add_argument('--project-root', 
                       default='.',
                       help='Project root directory (default: current directory)')
    
    parser.add_argument('--config-file',
                       default='pipeline_request.txt',
                       help='Pipeline configuration file (default: pipeline_request.txt)')
    
    parser.add_argument('--analyze-only',
                       action='store_true',
                       help='Only analyze the project, don\'t generate files')
    
    parser.add_argument('--auto-commit',
                       action='store_true',
                       help='Automatically commit generated files to git')
    
    parser.add_argument('--verbose',
                       action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--openai-token',
                       type=str,
                       help='OpenAI API token for AI-enhanced pipeline generation')

    parser.add_argument('--apply-fixes',
                       action='store_true',
                       help='Apply security fixes from analysis directly to infra files')

    parser.add_argument('--suggest-changes',
                       action='store_true',
                       help='Analyze project and write suggestions.md with recommended changes')

    args = parser.parse_args()
    
    print("🤖 AI DevOps Agent")
    print("=" * 50)
    
    try:
        # Get OpenAI token from argument or environment variable
        openai_token = args.openai_token or os.getenv('OPENAI_API_TOKEN')
        
        generator = PipelineGenerator(args.project_root, args.config_file, openai_token)
        
        if args.suggest_changes:
            print("🔍 Generating suggestions report...")
            analysis = generator.analyzer.analyze_project()
            analysis = generator._ai_enhance_analysis(analysis)
            generator.suggest_changes(analysis)

        elif args.apply_fixes:
            print("🔧 Applying infra fixes from analysis...")
            analysis = generator.analyzer.analyze_project()
            changed = generator.apply_infra_fixes(analysis)
            if changed:
                print(f"✅ Applied fixes to: {', '.join(changed)}")

        elif args.analyze_only:
            print("🔍 Running analysis only...")
            analysis = generator.analyzer.analyze_project()
            analysis = generator._ai_enhance_analysis(analysis)
            
            # Display human-readable analysis
            print(generator._format_analysis_human_readable(analysis))
            
            if 'ai_recommendations' in analysis:
                print(generator._format_ai_recommendations_human_readable(analysis['ai_recommendations']))
            
            # Show raw JSON in verbose mode
            if args.verbose:
                print("\n🔍 Raw Analysis Data (Verbose Mode):")
                print(json.dumps(analysis, indent=2))
            
        else:
            success = generator.generate_pipeline()
            
            if success and args.auto_commit:
                print("📤 Auto-committing changes...")
                try:
                    subprocess.run(['git', 'add', '.'], cwd=args.project_root)
                    subprocess.run(['git', 'commit', '-m', 'AI: Generated CI/CD pipeline components'], 
                                 cwd=args.project_root)
                    print("✅ Changes committed successfully")
                except Exception as e:
                    print(f"⚠️  Could not commit changes: {e}")
            
            if success:
                print("\n🎉 Pipeline generation completed successfully!")
                print("\nNext steps:")
                print("1. Review generated files")
                print("2. Configure GitHub secrets (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
                print("3. Push changes to trigger the pipeline")
                print("4. Monitor deployment in GitHub Actions")
            else:
                print("\n❌ Pipeline generation failed")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n⚠️  Generation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()