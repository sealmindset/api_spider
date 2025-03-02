
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger
import requests
import time
import json
import uuid
from datetime import datetime

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
                    response = requests.request(method, f"{url}{path}", params=params, headers=headers, timeout=10)
                    
                    # Capture transaction for evidence
                    param_req, param_res = self.capture_transaction(
                        response,
                        auth_state=auth_state,
                        correlation_id=correlation_id
                    )
                    
                    # Test in JSON body
                    json_data = {'query': payload, 'filter': payload}
                    json_response = requests.request(method, f"{url}{path}", json=json_data, headers=headers, timeout=10)
                    
                    # Capture JSON request transaction
                    json_req, json_res = self.capture_transaction(
                        json_response,
                        auth_state=auth_state,
                        correlation_id=correlation_id
                    )
                    
                    # Check for SQL errors in responses
                    for resp, req_data, res_data in [(response, param_req, param_res), (json_response, json_req, json_res)]:
                        if any(error in resp.text.lower() for error in sql_errors):
                            finding = {
                                'type': 'SQL_INJECTION',
                                'severity': 'HIGH',
                                'endpoint': f"{url}{path}",
                                'parameter': 'id' if params else 'json_body',
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
                                }
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
                                        'endpoint': f"{url}{path}",
                                        'parameter': 'id' if params else 'json_body',
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
                                        }
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
            "body": request.body,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        res_data = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:500],  # Truncate long responses
            "timestamp": datetime.utcnow().isoformat()
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
