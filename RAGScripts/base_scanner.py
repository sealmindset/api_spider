
#!/usr/bin/env python3

import json
import sys
import argparse
import logging
import requests
from typing import Dict, List, Optional, Union
from datetime import datetime
import uuid
from urllib.parse import urljoin
import time
from abc import ABC, abstractmethod
from .utils.logger import setup_logger
from typing import List, Dict, Any
from .llm_analyzer import LLMAnalyzer

class BaseScanner(ABC):
    def __init__(self):
        self.logger = setup_logger(self.__class__.__name__)
        self.time = None
        self.findings = []
        self.session = requests.Session()
        self.llm_analyzer = LLMAnalyzer()
        self.context = {}
        
        # Initialize finding formatter
        from .utils.finding_formatter import FindingFormatter
        self.finding_formatter = FindingFormatter()
        # Remediation templates for common vulnerability types
        self.remediation_templates = {
            'SQLI': {
                'description': 'SQL Injection vulnerability allows attackers to manipulate database queries',
                'impact': 'Data theft, unauthorized access, data manipulation',
                'steps': [
                    'Use parameterized queries or prepared statements',
                    'Implement input validation and sanitization',
                    'Apply principle of least privilege for database users',
                    'Enable proper error handling to avoid SQL error disclosure'
                ]
            },
            'XSS': {
                'description': 'Cross-site scripting allows attackers to inject malicious scripts',
                'impact': 'Session hijacking, credential theft, defacement',
                'steps': [
                    'Implement context-aware output encoding',
                    'Use Content-Security-Policy headers',
                    'Validate and sanitize all user inputs',
                    'Use modern frameworks with built-in XSS protections'
                ]
            },
            'IDOR': {
                'description': 'Insecure Direct Object References allow unauthorized access to resources',
                'impact': 'Data leakage, unauthorized access to sensitive information',
                'steps': [
                    'Implement proper access control checks',
                    'Use indirect reference maps',
                    'Validate user permissions for each resource access',
                    'Audit all resource access endpoints'
                ]
            },
            'AUTH_BYPASS': {
                'description': 'Authentication bypass vulnerability allows unauthorized access',
                'impact': 'Unauthorized access to protected resources, privilege escalation',
                'steps': [
                    'Implement proper session management',
                    'Use secure authentication mechanisms',
                    'Apply role-based access control',
                    'Regular security audits of authentication logic'
                ]
            },
            'UNAUTHORIZED_PASSWORD_CHANGE': {
                'description': 'Allows attackers to change passwords of other users without proper authorization',
                'impact': 'Account takeover, privilege escalation, unauthorized access',
                'steps': [
                    'Enforce proper authorization checks for password changes',
                    'Require current password verification',
                    'Implement proper session validation',
                    'Add rate limiting for password change attempts',
                    'Send notifications for password changes'
                ]
            }
        }

    @abstractmethod
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Base scan method to be implemented by child classes
        
        Args:
            url (str): Target URL to scan
            method (str): HTTP method to use
            path (str): API endpoint path
            response (requests.Response): Initial response from the endpoint
            token (str, optional): Authentication token
            headers (Dict[str, str], optional): Request headers
            tokens (Dict[str, List[Dict[str, Any]]], optional): Discovered tokens from other scanners
            context (Dict[str, Any], optional): Shared context from previous scans
            
        Returns:
            List[Dict[str, Any]]: List of discovered vulnerabilities
        """
        raise NotImplementedError("Scan method must be implemented by child classes")
        
    def format_findings(self, findings: List[Dict[str, Any]], url: str = None, path: str = None) -> List[Dict[str, Any]]:
        """Format findings using the standardized formatter
        
        Args:
            findings: List of raw findings from scanner
            url: Base URL of the target
            path: API endpoint path
            
        Returns:
            List[Dict[str, Any]]: List of standardized findings
        """
        formatted_findings = []
        for finding in findings:
            formatted = self.finding_formatter.format_finding(finding, url, path)
            formatted_findings.append(formatted)
        return formatted_findings

    def capture_transaction(self, response: requests.Response, auth_state: Dict[str, Any], correlation_id: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """Capture comprehensive request/response transaction details with auth state and timing"""
        # Capture detailed request information including raw data for replay
        request_data = {
            'method': response.request.method,
            'url': response.request.url,
            'headers': dict(response.request.headers),
            'body': response.request.body.decode('utf-8', errors='ignore') if response.request.body else None,
            'raw_body': response.request.body,
            'query_params': dict(response.request._Request__args) if hasattr(response.request, '_Request__args') else {},
            'auth_state': auth_state,
            'correlation_id': correlation_id,
            'timestamp': datetime.utcnow().isoformat(),
            'content_type': response.request.headers.get('Content-Type'),
            'content_length': len(response.request.body) if response.request.body else 0,
            'curl_command': self._generate_curl_command(response.request),
            'url_components': {
                'scheme': response.request.url.split('://')[0] if '://' in response.request.url else None,
                'host': response.request.url.split('://')[1].split('/')[0] if '://' in response.request.url else None,
                'path': '/' + '/'.join(response.request.url.split('://')[1].split('/')[1:]) if '://' in response.request.url else response.request.url
            }
        }
        
        # Capture detailed response information including evidence of vulnerability
        response_data = {
            'status_code': response.status_code,
            'reason': response.reason,
            'headers': dict(response.headers),
            'body': response.text,
            'raw_body': response.content,
            'content_type': response.headers.get('Content-Type'),
            'content_length': len(response.content),
            'cookies': dict(response.cookies),
            'elapsed': response.elapsed.total_seconds(),
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': correlation_id,
            'is_redirect': response.is_redirect,
            'apparent_encoding': response.apparent_encoding,
            'history': [{
                'url': r.url,
                'status_code': r.status_code,
                'headers': dict(r.headers),
                'body': r.text[:500]  # Include partial response body for redirect chain
            } for r in response.history],
            'encoding': response.encoding,
            'is_permanent_redirect': response.is_permanent_redirect,
            'links': response.links,
            'error_indicators': self._detect_error_indicators(response)
        }
        
        # Add timing information
        response_data['timing'] = {
            'total_elapsed': response.elapsed.total_seconds(),
            'connection_time': getattr(response.raw, 'connection_time', None),
            'start_time': getattr(response.raw, 'start_time', None),
            'end_time': datetime.utcnow().isoformat()
        }
        
        # Add authentication context
        if auth_state:
            request_data['auth_context'] = {
                'auth_type': auth_state.get('auth_type'),
                'auth_method': auth_state.get('auth_method'),
                'token_type': auth_state.get('token_type'),
                'user_context': auth_state.get('user_context'),
                'permissions': auth_state.get('permissions'),
                'session_data': auth_state.get('session_data'),
                'token_expiry': auth_state.get('token_expiry'),
                'token_claims': auth_state.get('token_claims'),
                'scope': auth_state.get('scope')
            }
        
        # Add security headers analysis
        response_data['security_headers'] = {
            'x_frame_options': response.headers.get('X-Frame-Options'),
            'x_content_type_options': response.headers.get('X-Content-Type-Options'),
            'x_xss_protection': response.headers.get('X-XSS-Protection'),
            'strict_transport_security': response.headers.get('Strict-Transport-Security'),
            'content_security_policy': response.headers.get('Content-Security-Policy'),
            'referrer_policy': response.headers.get('Referrer-Policy')
        }
        
        return request_data, response_data
        
    def _generate_curl_command(self, request) -> str:
        """Generate a curl command that can reproduce the request"""
        command = [f"curl -X {request.method}"]
        
        # Add headers
        for header, value in request.headers.items():
            if header.lower() not in ['content-length', 'host']:
                command.append(f"-H '{header}: {value}'")
                
        # Add request body if present
        if request.body:
            try:
                body = request.body.decode('utf-8')
                command.append(f"-d '{body}'")
            except UnicodeDecodeError:
                command.append("--data-binary @-")
                
        # Add the URL
        command.append(f"'{request.url}'")
        
        return " \
  ".join(command)
        
    def _detect_error_indicators(self, response) -> Dict[str, Any]:
        """Detect various error indicators in the response"""
        indicators = {
            'sql_errors': False,
            'stack_traces': False,
            'debug_info': False,
            'sensitive_data': False
        }
        
        # Check response body for various error patterns
        body_lower = response.text.lower()
        
        # SQL error detection
        sql_patterns = ['sql', 'mysql', 'postgresql', 'ora-', 'sqlstate']
        indicators['sql_errors'] = any(pattern in body_lower for pattern in sql_patterns)
        
        # Stack trace detection
        stack_patterns = ['exception', 'stack trace', 'debug', 'at line', 'file:']
        indicators['stack_traces'] = any(pattern in body_lower for pattern in stack_patterns)
        
        # Debug info detection
        debug_patterns = ['debug', 'development', 'test', 'beta']
        indicators['debug_info'] = any(pattern in body_lower for pattern in debug_patterns)
        
        # Sensitive data detection
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential']
        indicators['sensitive_data'] = any(pattern in body_lower for pattern in sensitive_patterns)
        
        return indicators

    def add_dependency(self, finding: Dict[str, Any], dependency_id: str) -> None:
        """Add dependency to a finding"""
        if 'dependencies' not in finding:
            finding['dependencies'] = []
        finding['dependencies'].append(dependency_id)

    def update_context(self, context_data: Dict[str, Any]) -> None:
        """Update scanner's context with new data"""
        self.context.update(context_data)

    def get_context(self) -> Dict[str, Any]:
        """Get scanner's current context"""
        return self.context

    def validate_finding(self, finding: Dict) -> bool:
        """Basic validation of finding format"""
        required_fields = ['type', 'severity', 'detail', 'evidence']
        return all(field in finding for field in required_fields)

    def validate_response(self, response) -> bool:
        """Basic response validation"""
        return True

    def setup_logging(self) -> None:
        """Configure structured logging for the scanner."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    def setup_arguments(self):
        """Set up command line arguments"""
        parser = argparse.ArgumentParser()
        parser.add_argument('--target', required=True, help='Target API URL')
        parser.add_argument('--auth', help='Authentication token or JSON credentials')
        self.args = parser.parse_args()
        
        # Handle auth argument
        if self.args.auth:
            try:
                # First try to parse as JSON
                self.auth = json.loads(self.args.auth)
            except json.JSONDecodeError:
                # If not JSON, treat as raw token
                self.auth = {"Authorization": f"Bearer {self.args.auth}"}
        else:
            self.auth = None
        self.target = self.args.target.rstrip('/')

    def configure_auth(self) -> None:
        """Configure authentication based on provided credentials."""
        auth_type = self.auth.get('type', 'none')
        credentials = self.auth.get('credentials', {})

        if auth_type == 'basic':
            self.session.auth = (
                credentials.get('username', ''),
                credentials.get('password', '')
            )
        elif auth_type == 'bearer':
            self.session.headers['Authorization'] = f"Bearer {credentials.get('token', '')}"
        elif auth_type == 'apikey':
            header_name = credentials.get('headerName', 'X-API-Key')
            self.session.headers[header_name] = credentials.get('apiKey', '')

    def make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Union[Dict, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        verify: bool = True,
        allow_redirects: bool = True
    ) -> requests.Response:
        """
        Make an HTTP request with full transaction capture.
        """
        url = urljoin(self.target, endpoint)
        request_headers = {**self.session.headers}
        if headers:
            request_headers.update(headers)

        start_time = time.time()
        self.logger.info(f"Making {method} request to {url}")

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                data=json.dumps(data) if isinstance(data, dict) else data,
                params=params,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects
            )
            elapsed = time.time() - start_time
            self.logger.info(f"Request completed in {elapsed:.2f}s with status {response.status_code}")
            return response

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            raise

    def capture_transaction(
        self,
        response: requests.Response,
        auth_state: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> tuple[Dict, Dict]:
        """
        Capture full HTTP transaction details from a response object.
        
        Args:
            response: The HTTP response object
            auth_state: Optional dict containing authentication state info
            correlation_id: Optional ID to correlate related requests
        """
        # Capture request details
        request_data = {
            "method": response.request.method,
            "url": response.request.url,
            "headers": dict(response.request.headers),
            "body": response.request.body or "",
            "timestamp": datetime.utcnow().isoformat(),
            "correlation_id": correlation_id or str(uuid.uuid4())
        }

        # Add auth state if provided
        if auth_state:
            request_data["auth_state"] = auth_state

        # Capture response details
        response_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "elapsed": response.elapsed.total_seconds(),
            "timestamp": datetime.utcnow().isoformat(),
            "correlation_id": request_data["correlation_id"]
        }

        return request_data, response_data

    def add_finding(
        self,
        title: str,
        description: str,
        endpoint: str,
        severity_level: str,
        impact: str,
        request: Dict,
        response: Dict,
        remediation: str = None,
        dependencies: List[str] = None,
        auth_state: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Add a security finding with full transaction details, attack chain info, and remediation guidance.
        """
        finding_id = str(uuid.uuid4())
        
        # Map severity level to standard format
        severity_map = {
            "bot": "LOW",
            "script": "MEDIUM",
            "tier1": "MEDIUM",
            "tier2": "HIGH",
            "tier3": "CRITICAL"
        }
        
        # Determine vulnerability type from title
        vuln_type = title.upper().replace(" ", "_")
        
        # Get remediation guidance from templates if available
        remediation_guidance = None
        if vuln_type in self.remediation_templates:
            remediation_guidance = self.remediation_templates[vuln_type]
        
        # Build attack chain if dependencies exist
        attack_chain = None
        if dependencies:
            attack_chain = {
                'steps': [],
                'auth_states': [],
                'impact_path': []
            }
            
            # Add current finding as final step in chain
            attack_chain['steps'].append({
                'finding_id': finding_id,
                'type': vuln_type,
                'description': description
            })
            
            # Add auth state if available
            if auth_state:
                attack_chain['auth_states'].append(auth_state)
        
        finding = {
            "id": finding_id,
            "title": title,
            "type": vuln_type,
            "description": description,
            "endpoint": endpoint,
            "severity": {
                "level": severity_map.get(severity_level, severity_level),
                "description": self.get_severity_description(severity_level)
            },
            "impact": impact,
            "request": request,
            "response": response,
            "remediation": remediation_guidance or remediation,
            "timestamp": datetime.utcnow().isoformat(),
            "scanner": self.__class__.__name__
        }
        
        # Add dependencies and attack chain if available
        if dependencies:
            finding["dependencies"] = dependencies
            finding["attack_chain"] = attack_chain
        
        # Analyze finding with LLM for additional context and insights
        llm_analysis = self.llm_analyzer.analyze_finding(finding)
        if llm_analysis:
            finding["llm_analysis"] = llm_analysis
        
        self.logger.info(f"Adding finding: {title} ({severity_level})")
        self.findings.append(finding)
        return finding

    def get_severity_description(self, level: str) -> str:
        """Get the description for a severity level."""
        descriptions = {
            "bot": "Bot - Automated attacks, Low complexity, High volume",
            "script": "Script Kiddie - Basic exploitation, Known vulnerabilities, Common tools",
            "tier1": "Tier 1 Validator - Intermediate threats, Some customization, Basic chaining",
            "tier2": "Tier 2 Hacker - Advanced attacks, Custom exploits, Complex chains",
            "tier3": "Tier 3 Elite - Sophisticated exploits, Zero-days, Advanced persistence"
        }
        return descriptions.get(level, "Unknown severity level")

    def run(self) -> None:
        """
        Main execution method to be implemented by scanner subclasses.
        """
        raise NotImplementedError("Subclasses must implement run()")

    def execute(self) -> None:
        """
        Execute the scanner with proper error handling and output formatting.
        """
        start_time = time.time()
        self.logger.info(f"Starting scan of {self.target}")

        try:
            self.run()
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)
            self.add_finding(
                "Scanner Error",
                f"Error during scan execution: {str(e)}",
                self.target,
                "bot",
                "Scanner failed to complete execution",
                {"error": str(e)},
                {"error": "Scan failed"},
                "Check scanner logs and fix implementation issues"
            )
        finally:
            elapsed = time.time() - start_time
            self.logger.info(f"Scan completed in {elapsed:.2f}s with {len(self.findings)} findings")
            print(json.dumps(self.findings))

if __name__ == "__main__":
    print("This is a base scanner class and should not be run directly")
    sys.exit(1)
