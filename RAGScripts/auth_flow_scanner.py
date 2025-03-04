#!/usr/bin/env python3

import requests
import yaml
import json
import time
import logging
import random
import string
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, quote


def setup_scanner_logger(name: str) -> logging.Logger:
    """Configure logging for the scanner"""
    logger = logging.getLogger(name)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    return logger


class AuthFlowScanner:
    """Scanner for testing authentication flow, account creation, and rate limiting"""
    
    def __init__(self, base_url: str, swagger_file: str, logger: Optional[logging.Logger] = None, additional_swagger_files: Optional[List[str]] = None):
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
        self.base_url = base_url.rstrip('/')
        self.swagger_file = swagger_file
        self.additional_swagger_files = additional_swagger_files or []
        self.logger = logger or setup_scanner_logger("auth_flow_scanner")
        self.swagger_spec = self._load_swagger(self.swagger_file)
        self.additional_specs = [self._load_swagger(file) for file in self.additional_swagger_files]
        self.endpoints = self._extract_endpoints(self.swagger_spec)
        self.additional_endpoints = [self._extract_endpoints(spec) for spec in self.additional_specs]
        self.findings = []
        self.accounts = []
        self.tokens = {}
        self.rate_limit_findings = []
        
    def _load_swagger(self, swagger_file: str) -> Dict:
        """Load the Swagger/OpenAPI specification file"""
        try:
            with open(swagger_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading Swagger file {swagger_file}: {str(e)}")
            raise
    
    def _extract_endpoints(self, swagger_spec: Dict) -> Dict:
        """Extract endpoints from the Swagger specification"""
        endpoints = {}
        paths = swagger_spec.get('paths', {})
        
        for path, methods in paths.items():
            endpoints[path] = {}
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoints[path][method.lower()] = {
                        'summary': details.get('summary', ''),
                        'description': details.get('description', ''),
                        'tags': details.get('tags', []),
                        'security': details.get('security', []),
                        'request_body': details.get('requestBody', {}),
                        'responses': details.get('responses', {})
                    }
        
        return endpoints
    
    def _get_schema_ref(self, ref: str, swagger_spec: Optional[Dict] = None) -> Dict:
        """Resolve a schema reference in the Swagger spec"""
        if not ref.startswith('#/components/schemas/'):
            return {}
        
        spec = swagger_spec or self.swagger_spec
        schema_name = ref.replace('#/components/schemas/', '')
        return spec.get('components', {}).get('schemas', {}).get(schema_name, {})
    
    def _generate_random_email(self, prefix: str = "user") -> str:
        """Generate a random email address"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{prefix}_{random_str}@example.com"
    
    def _find_endpoint_by_tag_and_summary(self, tag: str, summary_keywords: List[str]) -> Optional[Dict]:
        """Find an endpoint by tag and summary keywords in primary and additional Swagger files"""
        # First check for registration endpoint directly in paths
        if 'register' in summary_keywords:
            for path, methods in self.swagger_spec.get('paths', {}).items():
                if '/register' in path.lower():
                    for method, details in methods.items():
                        if method.lower() == 'post':
                            return {
                                'path': path,
                                'method': method,
                                'details': details,
                                'swagger_file': self.swagger_file,
                                'swagger_spec': self.swagger_spec
                            }
        
        # Then check the primary Swagger file
        endpoint = self._find_endpoint_in_spec(self.endpoints, tag, summary_keywords)
        if endpoint:
            endpoint['swagger_file'] = self.swagger_file
            endpoint['swagger_spec'] = self.swagger_spec
            return endpoint
            
        # Then check additional Swagger files
        for i, endpoints in enumerate(self.additional_endpoints):
            endpoint = self._find_endpoint_in_spec(endpoints, tag, summary_keywords)
            if endpoint:
                endpoint['swagger_file'] = self.additional_swagger_files[i]
                endpoint['swagger_spec'] = self.additional_specs[i]
                return endpoint
                
        return None
        
    def _find_endpoint_in_spec(self, endpoints: Dict, tag: str, summary_keywords: List[str]) -> Optional[Dict]:
        """Find an endpoint by tag and summary keywords in a specific endpoints dictionary"""
        for path, methods in endpoints.items():
            for method, details in methods.items():
                # Check for both 'users' and 'Authentication' tags
                if tag in details['tags'] or 'users' in details['tags']:
                    summary = details['summary'].lower()
                    description = details.get('description', '').lower()
                    path_lower = path.lower()
                    
                    # Handle hyphenated keywords and common variations
                    normalized_summary = summary.replace('-', ' ').replace('_', ' ')
                    normalized_description = description.replace('-', ' ').replace('_', ' ')
                    
                    # Check both summary and description for keywords
                    summary_match = all(keyword.lower() in normalized_summary for keyword in summary_keywords)
                    description_match = all(keyword.lower() in normalized_description for keyword in summary_keywords)
                    
                    # Additional check for registration variations
                    if 'register' in summary_keywords:
                        variations = ['register', 'signup', 'sign up', 'sign-up', 'create account', 'new user']
                        summary_match = summary_match or any(var in normalized_summary for var in variations)
                        description_match = description_match or any(var in normalized_description for var in variations)
                        
                        # Check if registration-related terms appear in the path
                        path_match = any(var in path_lower for var in ['/register', '/signup', '/sign-up', '/users/v1/register'])
                        
                        if path_match or summary_match or description_match:
                            return {
                                'path': path,
                                'method': method,
                                'details': details
                            }
                    
                    # Additional check for sign-in variations
                    if 'sign-in' in summary_keywords or 'login' in summary_keywords:
                        variations = ['signin', 'sign in', 'login', 'log in']
                        summary_match = summary_match or any(var in normalized_summary for var in variations)
                        description_match = description_match or any(var in normalized_description for var in variations)
                    
                    if summary_match or description_match:
                        return {
                            'path': path,
                            'method': method,
                            'details': details
                        }
        return None
    
    def _get_current_test_phase(self) -> str:
        """Get the current test phase for logging purposes"""
        return "Authentication Flow Test"
    
    def _get_current_test_case(self) -> str:
        """Get the current test case for logging purposes"""
        return "Account Registration"
    
    def _log_request_response(self, method: str, url: str, headers: Dict, payload: Any, response: requests.Response) -> None:
        """Log the full request and response details"""
        request_log = {
            "request": {
                "method": method,
                "url": url,
                "headers": headers,
                "payload": payload,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            },
            "response": {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body": self._safe_parse_json(response),
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "response_time": response.elapsed.total_seconds()
            },
            "test_context": {
                "test_phase": self._get_current_test_phase(),
                "test_case": self._get_current_test_case()
            }
        }
        
        # Log to both debug and file
        self.logger.debug(f"Request/Response: {json.dumps(request_log, indent=2)}")
        
        # Ensure logs directory exists and create a structured log file
        log_file = f'logs/auth_flow_test_{time.strftime("%Y%m%d")}.log'
        with open(log_file, 'a') as f:
            f.write(f"\n{'-'*80}\n")
            f.write(f"Test Phase: {request_log['test_context']['test_phase']}\n")
            f.write(f"Test Case: {request_log['test_context']['test_case']}\n")
            f.write(f"Timestamp: {request_log['request']['timestamp']}\n")
            f.write(f"Request: {method} {url}\n")
            f.write(f"Headers: {json.dumps(headers, indent=2)}\n")
            f.write(f"Payload: {json.dumps(payload, indent=2)}\n")
            f.write(f"Response Status: {response.status_code}\n")
            f.write(f"Response Time: {request_log['response']['response_time']} seconds\n")
            f.write(f"Response Headers: {json.dumps(dict(response.headers), indent=2)}\n")
            f.write(f"Response Body: {json.dumps(self._safe_parse_json(response), indent=2)}\n")
        return request_log
    
    def _safe_parse_json(self, response: requests.Response) -> Dict:
        """Safely parse JSON response"""
        try:
            return response.json()
        except ValueError:
            return {"content": response.text[:200]}
    
    def register_initial_account(self) -> Dict:
        """Register an initial account for testing"""
        # Find the registration endpoint - try both Authentication and users tags
        register_endpoint = self._find_endpoint_by_tag_and_summary("Authentication", ["register"])
        
        if not register_endpoint:
            # Try with 'users' tag if 'Authentication' tag didn't work
            register_endpoint = self._find_endpoint_by_tag_and_summary("users", ["register"])
        
        if not register_endpoint:
            self.logger.error("Registration endpoint not found in any Swagger spec")
            return {}
        
        path = register_endpoint['path']
        method = register_endpoint['method']
        url = urljoin(self.base_url, path)
        swagger_spec = register_endpoint.get('swagger_spec', self.swagger_spec)
        
        # Log which Swagger file the endpoint was found in
        swagger_file = register_endpoint.get('swagger_file', self.swagger_file)
        self.logger.info(f"Using registration endpoint from {swagger_file}: {method} {path}")
        
        # Get the request schema
        request_schema = {}
        if 'request_body' in register_endpoint['details']:
            content = register_endpoint['details']['request_body'].get('content', {})
            schema = content.get('application/json', {}).get('schema', {})
            schema_ref = schema.get('$ref')
            if schema_ref:
                request_schema = self._get_schema_ref(schema_ref, swagger_spec)
            else:
                # Handle inline schema (no $ref)
                request_schema = schema
        
        # Create the registration payload
        email = self._generate_random_email("user_initial")
        password = "Password#123"
        
        payload = {
            "email": email,
            "password": password
        }
        
        # Add any additional required fields from the schema
        required_fields = request_schema.get('required', [])
        properties = request_schema.get('properties', {})
        
        for field in required_fields:
            if field not in payload and field in properties:
                # Add default values for other required fields
                payload[field] = "test_value"
        
        self.logger.info(f"Registering initial account with email: {email}")
        
        try:
            response = requests.request(method, url, json=payload)
            log_entry = self._log_request_response(method, url, {}, payload, response)
            
            if response.status_code == 201 or response.status_code == 200:
                account_info = {
                    "email": email,
                    "password": password,
                    "response": response.json() if response.text else {}
                }
                self.accounts.append(account_info)
                self.logger.info(f"Successfully registered account: {email}")
                return account_info
            else:
                self.logger.error(f"Failed to register account. Status: {response.status_code}, Response: {response.text}")
                return {}
                
        except Exception as e:
            self.logger.error(f"Error during registration: {str(e)}")
            return {}
    
    def test_rate_limiting(self, num_accounts: int = 50) -> List[Dict]:
        """Test rate limiting by creating multiple accounts in rapid succession"""
        register_endpoint = self._find_endpoint_by_tag_and_summary("Authentication", ["register"])
        
        if not register_endpoint:
            self.logger.error("Registration endpoint not found in Swagger spec")
            return []
        
        path = register_endpoint['path']
        method = register_endpoint['method']
        url = urljoin(self.base_url, path)
        
        rate_limit_findings = []
        rate_limit_headers = ['ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset', 'retry-after']
        
        self.logger.info(f"Testing rate limiting by creating {num_accounts} accounts")
        
        for i in range(num_accounts):
            email = self._generate_random_email(f"user{i+1}")
            password = "Password#123"
            
            payload = {
                "email": email,
                "password": password
            }
            
            try:
                response = requests.request(method, url, json=payload)
                log_entry = self._log_request_response(method, url, {}, payload, response)
                
                # Check for rate limiting responses
                if response.status_code == 429:
                    self.logger.info(f"Rate limiting detected after {i+1} requests")
                    rate_limit_finding = {
                        "type": "RATE_LIMITING_DETECTED",
                        "severity": "INFO",
                        "detail": f"Rate limiting detected after {i+1} requests",
                        "evidence": {
                            "request_count": i+1,
                            "status_code": response.status_code,
                            "headers": {k: v for k, v in response.headers.items() if k.lower() in rate_limit_headers},
                            "response": self._safe_parse_json(response)
                        }
                    }
                    rate_limit_findings.append(rate_limit_finding)
                    self.rate_limit_findings.append(rate_limit_finding)
                    break
                
                # Check for rate limit headers even on successful responses
                rate_limit_header_present = any(h.lower() in [k.lower() for k in response.headers.keys()] for h in rate_limit_headers)
                if rate_limit_header_present:
                    self.logger.info(f"Rate limit headers detected in response {i+1}")
                    headers_finding = {
                        "type": "RATE_LIMIT_HEADERS_PRESENT",
                        "severity": "INFO",
                        "detail": "Rate limit headers present in response",
                        "evidence": {
                            "request_count": i+1,
                            "status_code": response.status_code,
                            "headers": {k: v for k, v in response.headers.items() if k.lower() in rate_limit_headers}
                        }
                    }
                    rate_limit_findings.append(headers_finding)
                
                if response.status_code == 201 or response.status_code == 200:
                    account_info = {
                        "email": email,
                        "password": password,
                        "response": response.json() if response.text else {}
                    }
                    self.accounts.append(account_info)
                
                # Add a small delay between requests to avoid overwhelming the server
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error during rate limit testing: {str(e)}")
        
        if not rate_limit_findings:
            no_rate_limit_finding = {
                "type": "NO_RATE_LIMITING_DETECTED",
                "severity": "MEDIUM",
                "detail": f"No rate limiting detected after {num_accounts} rapid registration attempts",
                "evidence": {
                    "request_count": num_accounts,
                    "accounts_created": len(self.accounts)
                }
            }
            rate_limit_findings.append(no_rate_limit_finding)
            self.rate_limit_findings.append(no_rate_limit_finding)
        
        self.logger.info(f"Created {len(self.accounts)} accounts during rate limit testing")
        return rate_limit_findings
    
    def verify_accounts(self) -> List[Dict]:
        """Verify that each created account exists"""
        check_endpoint = self._find_endpoint_by_tag_and_summary("Authentication", ["check"])
        
        if not check_endpoint:
            self.logger.error("User check endpoint not found in Swagger spec")
            return []
        
        path = check_endpoint['path']
        method = check_endpoint['method']
        
        verification_results = []
        
        for account in self.accounts:
            email = account["email"]
            # URL encode the email parameter
            encoded_email = quote(email)
            
            # Handle path parameters or query parameters
            if '{email}' in path:
                # Path parameter
                url = urljoin(self.base_url, path.replace('{email}', encoded_email))
                params = {}
            else:
                # Query parameter
                url = urljoin(self.base_url, path)
                params = {"email": email}
            
            self.logger.info(f"Verifying account: {email}")
            
            try:
                response = requests.request(method, url, params=params)
                log_entry = self._log_request_response(method, url, {}, params, response)
                
                if response.status_code == 200:
                    response_data = response.json()
                    verification_result = {
                        "email": email,
                        "exists": True,
                        "details": response_data
                    }
                    
                    # Check if the response matches expected schema
                    if 'user' in response_data and 'existsInBreatheIQ' in response_data['user']:
                        if not response_data['user']['existsInBreatheIQ']:
                            self.logger.warning(f"Account {email} exists but existsInBreatheIQ is false")
                            verification_result["warning"] = "Account exists but existsInBreatheIQ is false"
                    
                    verification_results.append(verification_result)
                else:
                    self.logger.error(f"Failed to verify account {email}. Status: {response.status_code}")
                    verification_results.append({
                        "email": email,
                        "exists": False,
                        "error": f"Status code: {response.status_code}"
                    })
            
            except Exception as e:
                self.logger.error(f"Error verifying account {email}: {str(e)}")
                verification_results.append({
                    "email": email,
                    "exists": False,
                    "error": str(e)
                })
        
        return verification_results
    
    def authenticate_account(self, account: Dict) -> Dict:
        """Authenticate using the sign-in endpoint and extract tokens"""
        login_endpoint = self._find_endpoint_by_tag_and_summary("Authentication", ["sign-in"])
        
        if not login_endpoint:
            # Try alternative keywords if sign-in endpoint not found
            login_endpoint = self._find_endpoint_by_tag_and_summary("Authentication", ["login"])
            if not login_endpoint:
                self.logger.error("Sign-in endpoint not found in Swagger spec")
                return {}
        
        path = login_endpoint['path']
        method = login_endpoint['method']
        url = urljoin(self.base_url, path)
        
        email = account.get("email")
        password = account.get("password")
        
        if not email or not password:
            self.logger.error("Missing email or password for authentication")
            return {}
        
        payload = {
            "email": email,
            "password": password
        }
        
        # Add FCM token if required by the schema
        request_schema = {}
        if 'request_body' in login_endpoint['details']:
            content = login_endpoint['details']['request_body'].get('content', {})
            schema_ref = content.get('application/json', {}).get('schema', {}).get('$ref')
            if schema_ref:
                request_schema = self._get_schema_ref(schema_ref)
                if 'fcmToken' in request_schema.get('properties', {}):
                    payload["fcmToken"] = "test_fcm_token_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        self.logger.info(f"Authenticating account: {email}")
        
        try:
            response = requests.request(method, url, json=payload)
            log_entry = self._log_request_response(method, url, {}, payload, response)
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Extract tokens
                access_token = response_data.get("accessToken")
                id_token = response_data.get("idToken")
                refresh_token = response_data.get("refreshToken")
                
                if access_token and refresh_token:
                    token_info = {
                        "accessToken": access_token,
                        "idToken": id_token,
                        "refreshToken": refresh_token,
                        "email": email
                    }
                    
                    self.tokens[email] = token_info
                    self.logger.info(f"Successfully authenticated account: {email}")
                    
                    # Add finding for successful authentication
                    auth_finding = {
                        "type": "AUTHENTICATION_SUCCESSFUL",
                        "severity": "INFO",
                        "detail": f"Successfully authenticated user {email}",
                        "evidence": {
                            "email": email,
                            "tokens_received": ["accessToken", "idToken", "refreshToken"] if id_token else ["accessToken", "refreshToken"],
                            "response": response_data
                        }
                    }
                    self.findings.append(auth_finding)
                    
                    return token_info
                else:
                    self.logger.error(f"Missing tokens in authentication response for {email}")
                    return {}
            else:
                self.logger.error(f"Failed to authenticate account {email}. Status: {response.status_code}")
                
                # Add finding for authentication failure
                auth_failure_finding = {
                    "type": "AUTHENTICATION_FAILED",
                    "severity": "MEDIUM",
                    "detail": f"Failed to authenticate user {email}",
                    "evidence": {
                        "email": email,
                        "status_code": response.status_code,
                        "response": self._safe_parse_json(response)
                    }
                }
                self.findings.append(auth_failure_finding)
                
                return {}
                
        except Exception as e:
            self.logger.error(f"Error during authentication: {str(e)}")
            return {}
    
    def refresh_token(self, token_info: Dict) -> Dict:
        """Refresh tokens using the refresh token endpoint"""
        refresh_endpoint = self._find_endpoint_by_tag_and_summary("Authentication", ["refresh"])
        
        if not refresh_endpoint:
            self.logger.error("Refresh token endpoint not found in Swagger spec")
            return {}
        
        path = refresh_endpoint['path']
        method = refresh_endpoint['method']
        url = urljoin(self.base_url, path)
        
        refresh_token = token_info.get("refreshToken")
        email = token_info.get("email")
        
        if not refresh_token:
            self.logger.error("Missing refresh token")
            return {}
        
        payload = {
            "refreshToken": refresh_token
        }
        
        self.logger.info(f"Refreshing tokens for account: {email}")
        
        try:
            response = requests.request(method, url, json=payload)
            log_entry = self._log_request_response(method, url, {}, payload, response)
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Extract new tokens
                new_access_token = response_data.get("accessToken")
                new_id_token = response_data.get("idToken")
                
                if new_access_token:
                    # Update token info
                    token_info["accessToken"] = new_access_token
                    if new_id_token:
                        token_info["idToken"] = new_id_token
                    
                    # Update stored tokens
                    if email in self.tokens:
                        self.tokens[email] = token_info
                    
                    self.logger.info(f"Successfully refreshed tokens for account: {email}")
                    
                    # Add finding for successful token refresh
                    refresh_finding = {
                        "type": "TOKEN_REFRESH_SUCCESSFUL",
                        "severity": "INFO",
                        "detail": f"Successfully refreshed tokens for user {email}",
                        "evidence": {
                            "email": email,
                            "tokens_received": ["accessToken", "idToken"] if new_id_token else ["accessToken"],
                            "response": response_data
                        }
                    }
                    self.findings.append(refresh_finding)
                    
                    return token_info
                else:
                    self.logger.error(f"Missing access token in refresh response for {email}")
                    return {}
            else:
                self.logger.error(f"Failed to refresh tokens for account {email}. Status: {response.status_code}")
                
                # Add finding for token refresh failure
                refresh_failure_finding = {
                    "type": "TOKEN_REFRESH_FAILED",
                    "severity": "MEDIUM",
                    "detail": f"Failed to refresh tokens for user {email}",
                    "evidence": {
                        "email": email,
                        "status_code": response.status_code,
                        "response": self._safe_parse_json(response)
                    }
                }
                self.findings.append(refresh_failure_finding)
                
                return {}
                
        except Exception as e:
            self.logger.error(f"Error during token refresh: {str(e)}")
            return {}
    
    def make_authenticated_requests(self, token_info: Dict) -> List[Dict]:
        """Make authenticated requests to various endpoints"""
        if not token_info or "accessToken" not in token_info:
            self.logger.error("No valid access token available for authenticated requests")
            return []
        
        access_token = token_info["accessToken"]
        id_token = token_info.get("idToken")
        email = token_info.get("email")
        
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        if id_token:
            headers["idtoken"] = id_token
        
        # Find endpoints that require authentication
        authenticated_endpoints = []
        for path, methods in self.endpoints.items():
            for method, details in methods.items():
                if details.get('security') and 'bearerAuth' in str(details.get('security')):
                    authenticated_endpoints.append({
                        'path': path,
                        'method': method,
                        'details': details
                    })
        
        # Filter for specific endpoints mentioned in the requirements
        target_endpoints = [
            ("User", ["details"]),  # Get User Details
            ("User", ["subscription"]),  # Get Subscription
            ("User", ["device", "information"]),  # Get Device Information
            ("User", ["personal", "health"])  # Get Personal Health Information
        ]
        
        selected_endpoints = []
        for tag, keywords in target_endpoints:
            endpoint = self._find_endpoint_by_tag_and_summary(tag, keywords)
            if endpoint:
                selected_endpoints.append(endpoint)
        
        if not selected_endpoints:
            self.logger.warning("No target authenticated endpoints found in Swagger spec")
            # Fall back to using any authenticated endpoints
            selected_endpoints = authenticated_endpoints[:4] if len(authenticated_endpoints) > 4 else authenticated_endpoints
        
        auth_request_results = []
        
        for endpoint in selected_endpoints:
            path = endpoint['path']
            method = endpoint['method']
            url = urljoin(self.base_url, path)
            
            self.logger.info(f"Making authenticated request to {method} {url}")
            
            try:
                response = requests.request(method, url, headers=headers)
                log_entry = self._log_request_response(method, url, headers, {}, response)
                
                result = {
                    "endpoint": path,
                    "method": method,
                    "status_code": response.status_code,
                    "response": self._safe_parse_json(response)
                }
                
                if response.status_code == 200:
                    self.logger.info(f"Successful authenticated request to {path}")
                    result["success"] = True
                else:
                    self.logger.warning(f"Failed authenticated request to {path}: {response.status_code}")
                    result["success"] = False
                    
                    # Add finding for failed authenticated request
                    if response.status_code == 401:
                        auth_failure_finding = {
                            "type": "AUTHENTICATED_REQUEST_UNAUTHORIZED",
                            "severity": "HIGH",
                            "detail": f"Authenticated request to {path} returned 401 Unauthorized",
                            "evidence": {
                                "email": email,
                                "endpoint": path,
                                "method": method,
                                "status_code": response.status_code,
                                "response": self._safe_parse_json(response)
                            }
                        }
                        self.findings.append(auth_failure_finding)
                
                auth_request_results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error making authenticated request to {path}: {str(e)}")
                auth_request_results.append({
                    "endpoint": path,
                    "method": method,
                    "error": str(e),
                    "success": False
                })
        
        return auth_request_results
    
    def run_assessment(self) -> Dict:
        """Run the complete API security assessment"""
        self.logger.info("Starting full authentication flow assessment")
        assessment_report = {
            "initial_account": {},
            "rate_limiting": {},
            "account_verification": {},
            "authentication": {},
            "authenticated_requests": {},
            "token_refresh": {},
            "findings": []
        }
        
        # Step 1: Register initial account
        self.logger.info("Step 1: Registering initial account")
        initial_account = self.register_initial_account()
        assessment_report["initial_account"] = {
            "success": bool(initial_account),
            "details": initial_account
        }
        
        # Step 2: Test rate limiting
        self.logger.info("Step 2: Testing rate limiting")
        rate_limit_findings = self.test_rate_limiting()
        assessment_report["rate_limiting"] = {
            "findings": rate_limit_findings,
            "accounts_created": len(self.accounts)
        }
        
        # Step 3: Verify accounts
        self.logger.info("Step 3: Verifying accounts")
        verification_results = self.verify_accounts()
        assessment_report["account_verification"] = {
            "results": verification_results,
            "success_count": sum(1 for result in verification_results if result.get("exists", False))
        }
        
        # Step 4: Authenticate with initial account
        self.logger.info("Step 4: Authenticating with initial account")
        token_info = {}
        if initial_account:
            token_info = self.authenticate_account(initial_account)
            assessment_report["authentication"] = {
                "success": bool(token_info),
                "tokens": token_info if token_info else {}
            }
        else:
            self.logger.error("Cannot authenticate - no initial account created")
            assessment_report["authentication"] = {
                "success": False,
                "error": "No initial account created"
            }
            
        # Step 5: Make authenticated requests
        self.logger.info("Step 5: Making authenticated requests")
        if token_info:
            auth_requests_results = self.make_authenticated_requests(token_info)
            assessment_report["authenticated_requests"] = {
                "results": auth_requests_results,
                "success_count": sum(1 for result in auth_requests_results if result.get("success", False))
            }
        else:
            self.logger.error("Cannot make authenticated requests - authentication failed")
            assessment_report["authenticated_requests"] = {
                "success": False,
                "error": "Authentication failed"
            }
            
        # Step 6: Refresh token
        self.logger.info("Step 6: Refreshing token")
        if token_info:
            refreshed_token_info = self.refresh_token(token_info)
            assessment_report["token_refresh"] = {
                "success": bool(refreshed_token_info),
                "tokens": refreshed_token_info if refreshed_token_info else {}
            }
        else:
            self.logger.error("Cannot refresh token - authentication failed")
            assessment_report["token_refresh"] = {
                "success": False,
                "error": "Authentication failed"
            }
        
        # Collect all findings
        assessment_report["findings"] = self.findings + self.rate_limit_findings
        
        self.logger.info("API Security Assessment completed")
        self.logger.info(f"Total findings: {len(assessment_report['findings'])}")
        
        # Log a summary of the assessment
        self._log_assessment_summary(assessment_report)
        
        return assessment_report
        
    def _log_assessment_summary(self, assessment_report: Dict) -> None:
        """Log a summary of the assessment results"""
        summary = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "base_url": self.base_url,
            "swagger_file": self.swagger_file,
            "initial_account": assessment_report["initial_account"]["success"],
            "rate_limiting": {
                "findings_count": len(assessment_report["rate_limiting"]["findings"]),
                "accounts_created": assessment_report["rate_limiting"]["accounts_created"]
            },
            "account_verification": {
                "success_count": assessment_report["account_verification"]["success_count"],
                "total_count": len(assessment_report["account_verification"]["results"])
            },
            "authentication": assessment_report["authentication"]["success"],
            "authenticated_requests": assessment_report["authenticated_requests"].get("success_count", 0),
            "token_refresh": assessment_report["token_refresh"].get("success", False),
            "total_findings": len(assessment_report["findings"])
        }
        
        # Log the summary
        self.logger.info(f"Assessment Summary: {json.dumps(summary, indent=2)}")
        
        # Write the summary to a file
        summary_file = f'logs/auth_flow_summary_{time.strftime("%Y%m%d_%H%M%S")}.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Assessment summary saved to {summary_file}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='API Security Assessment for Account Creation, Rate Limiting, and Authentication Flow')
    parser.add_argument('--url', default='http://localhost:3000/api/v1/mobile', help='Base URL of the API to scan')
    parser.add_argument('--swagger', default='swagger/snorefox.yml', help='Path to Swagger/OpenAPI specification file')
    parser.add_argument('--output', default='auth_flow_assessment.json', help='Output file for assessment report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logger
    logger = setup_scanner_logger("auth_flow_scanner")
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Run the assessment
        scanner = AuthFlowScanner(args.url, args.swagger, logger)
        assessment_report = scanner.run_assessment()
        
        # Save the report
        with open(args.output, 'w') as f:
            json.dump(assessment_report, f, indent=2)
        
        logger.info(f"Assessment report saved to {args.output}")
        
        # Print summary
        print("\nAPI Security Assessment Summary:")
        print(f"Initial account creation: {'Success' if assessment_report['initial_account']['success'] else 'Failed'}")
        print(f"Rate limiting test: {len(assessment_report['rate_limiting']['findings'])} findings")
        print(f"Account verification: {assessment_report['account_verification']['success_count']} of {len(assessment_report['account_verification']['results'])} accounts verified")
        print(f"Authentication: {'Success' if assessment_report['authentication']['success'] else 'Failed'}")
        if assessment_report['authentication']['success']:
            print(f"Authenticated requests: {assessment_report['authenticated_requests']['success_count']} of {len(assessment_report['authenticated_requests']['results'])} successful")
            print(f"Token refresh: {'Success' if assessment_report['token_refresh']['success'] else 'Failed'}")
        print(f"Total findings: {len(assessment_report['findings'])}")
        
    except Exception as e:
        logger.error(f"Error during assessment: {str(e)}")
        raise


if __name__ == '__main__':
    main()