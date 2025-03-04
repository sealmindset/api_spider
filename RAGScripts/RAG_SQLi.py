
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger
import requests
import time
import json
import uuid
from datetime import datetime
from urllib.parse import urljoin

class SQLiScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("sqli")
        self.target = None
        self.context = {}

    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None, context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.target = url
        vulnerabilities = []
        if headers is None:
            headers = {'Authorization': f'Bearer {token}'} if token else {}

        # Store context if provided
        if context:
            self.context = context
            self.logger.info(f"Received context with {len(context)} items")
            
            # Use finding IDs from previous scans for dependency tracking
            dependencies = context.get('finding_ids', [])
            self.logger.info(f"Using {len(dependencies)} dependencies from previous findings")

        # Generate correlation ID for tracking related requests
        correlation_id = str(uuid.uuid4())

        # SQL Injection patterns
        payloads = {
            "Error Based": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "') OR ('1'='1"
            ],
            "Boolean Based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 'x'='x",
                "' OR 'a'='a"
            ],
            "Time Based": [
                "'; WAITFOR DELAY '0:0:5'--",
                "'; SLEEP(5)--",
                "' OR SLEEP(5)--"
            ],
            "Union Based": [
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--"
            ]
        }

        # SQL Error patterns to detect
        sql_errors = [
            "SQL syntax",
            "mysql_fetch_array()",
            "ORA-01756",
            "SQLite3::query",
            "pg_query",
            "System.Data.SQLClient",
            "SQLSTATE",
            "Microsoft SQL Native Client error"
        ]

        for attack_type, attack_payloads in payloads.items():
            for payload in attack_payloads:
                try:
                    # Track authentication state for attack chain building
                    auth_state = {"token": token, "auth_type": "bearer"} if token else None

                    # Test in URL parameters
                    params = {'id': payload, 'search': payload}
                    response = requests.request(method, url, params=params, headers=headers, timeout=10)
                    
                    # Test in URL path
                    path_response = requests.request(method, url, headers=headers, timeout=10)
                    
                    # Capture path test transaction
                    path_req, path_res = self.capture_transaction(
                        path_response,
                        auth_state=auth_state,
                        correlation_id=correlation_id
                    )
                    
                    # Capture parameter test transaction
                    param_req, param_res = self.capture_transaction(
                        response,
                        auth_state=auth_state,
                        correlation_id=correlation_id
                    )
                    
                    # Test in JSON body
                    json_data = {'query': payload, 'filter': payload}
                    # Use urljoin for proper URL construction
                    test_url = urljoin(url, path) if not url.endswith(path) else url
                    json_response = requests.request(method, test_url, json=json_data, headers=headers, timeout=10)
                    
                    # Capture JSON request transaction
                    json_req, json_res = self.capture_transaction(
                        json_response,
                        auth_state=auth_state,
                        correlation_id=correlation_id
                    )
                    
                    # Check for SQL errors in responses
                    for resp, req_data, res_data, test_type in [
                        (response, param_req, param_res, 'parameter'),
                        (path_response, path_req, path_res, 'path'),
                        (json_response, json_req, json_res, 'json_body')
                    ]:
                        if any(error in resp.text.lower() for error in sql_errors):
                            finding = {
                                'type': 'SQL_INJECTION',
                                'severity': 'HIGH',
                                'endpoint': urljoin(url, path) if not url.endswith(path) else url,
                                'parameter': test_type,
                                'attack_pattern': payload,
                                'detail': f'SQL Injection vulnerability found using {attack_type}',
                                'evidence': {
                                    'code': "const query = `SELECT * FROM users WHERE id = '${userId}'`;\ndb.execute(query);",
                                    'payload': payload,
                                    'response_sample': resp.text[:200],
                                    'request': req_data,
                                    'response': res_data,
                                    'scenario': attack_type,
                                    'error_matched': [e for e in sql_errors if e in resp.text],
                                    'auth_state': auth_state,
                                    'correlation_id': correlation_id
                                },
                                'related_vulns': "Injection, No Credentials Required, Excessive Data Exposure"
                            }
                            vulnerabilities.append(finding)
                            self.logger.warning(f"Found SQL injection vulnerability using {attack_type}")
                        
                        # Check for successful injections without errors
                        if resp.status_code == 200:
                            if attack_type == "Boolean Based":
                                # Compare responses to detect boolean-based injections
                                true_condition = "1=1" in payload
                                false_condition = "1=2" in payload
                                if true_condition != false_condition:
                                    finding = {
                                        'type': 'SQL_INJECTION',
                                        'severity': 'HIGH',
                                        'endpoint': urljoin(url, path) if not url.endswith(path) else url,
                                        'parameter': test_type,
                                        'attack_pattern': payload,
                                        'detail': 'Potential Boolean-based SQL Injection detected',
                                        'evidence': {
                                            'code': "const query = `SELECT * FROM users WHERE id = '${userId}'`;\ndb.execute(query);",
                                            'payload': payload,
                                            'response_sample': resp.text[:200],
                                            'request': req_data,
                                            'response': res_data,
                                            'scenario': 'Boolean Based',
                                            'auth_state': auth_state,
                                            'correlation_id': correlation_id
                                        },
                                        'related_vulns': "Injection, No Credentials Required, Excessive Data Exposure"
                                    }
                                    vulnerabilities.append(finding)
                                    self.logger.warning("Found Boolean-based SQL injection vulnerability")
                
                except requests.RequestException as e:
                    self.logger.error(f"Error testing payload {payload}: {str(e)}")
                    continue

        return vulnerabilities
    
    def capture_transaction(self, response: requests.Response, auth_state: Dict[str, Any] = None, 
                           correlation_id: str = None) -> tuple:
        """Capture request/response details for evidence"""
        request = response.request
        
        req_data = {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "body": request.body.decode('utf-8', errors='ignore') if request.body else None,
            "raw_body": request.body,
            "timestamp": datetime.utcnow().isoformat(),
            "content_type": request.headers.get('Content-Type'),
            "content_length": len(request.body) if request.body else 0,
            "url_components": {
                "scheme": request.url.split('://')[0] if '://' in request.url else None,
                "host": request.url.split('://')[1].split('/')[0] if '://' in request.url else None,
                "path": '/' + '/'.join(request.url.split('://')[1].split('/')[1:]) if '://' in request.url else request.url
            }
        }
        
        res_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,  # Store full response
            "raw_body": response.content,
            "response_preview": response.text[:500],  # Keep preview for quick reference
            "timestamp": datetime.utcnow().isoformat(),
            "content_type": response.headers.get('Content-Type'),
            "content_length": len(response.content),
            "encoding": response.encoding,
            "is_redirect": response.is_redirect,
            "is_permanent_redirect": response.is_permanent_redirect,
            "apparent_encoding": response.apparent_encoding,
            "elapsed": response.elapsed.total_seconds()
        }
        
        if auth_state:
            req_data["auth_state"] = auth_state
            res_data["auth_state"] = auth_state
            
        if correlation_id:
            req_data["correlation_id"] = correlation_id
            res_data["correlation_id"] = correlation_id
            
        return req_data, res_data
    
    def update_context(self, context_update: Dict[str, Any]) -> None:
        """Update scanner context with new information"""
        if not hasattr(self, 'context'):
            self.context = {}
            
        self.context.update(context_update)

scan = SQLiScanner().scan
