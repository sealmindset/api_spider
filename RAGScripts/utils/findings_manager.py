#!/usr/bin/env python3

from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

class FindingsManager:
    def __init__(self, logger: logging.Logger):
        self.findings = []
        self.credentials = {}
        self.tokens = {}
        self.context = {}
        self.dependencies = {}
        self.attack_chains = {}
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
            'AUTH_BYPASS': {
                'description': 'Authentication bypass vulnerability allows unauthorized access',
                'impact': 'Unauthorized access to protected resources, privilege escalation',
                'steps': [
                    'Implement proper session management',
                    'Use secure authentication mechanisms',
                    'Apply role-based access control',
                    'Regular security audits of authentication logic'
                ]
            }
        }
        self.logger = logger

    def add_finding(self, finding: Dict[str, Any], dependencies: Optional[List[str]] = None) -> str:
        """Add a finding with dependencies, attack chain info, and remediation guidance"""
        finding_id = str(len(self.findings))
        finding['id'] = finding_id
        finding['timestamp'] = datetime.utcnow().isoformat()
        
        # Add remediation guidance
        vuln_type = finding.get('type')
        if vuln_type in self.remediation_templates:
            finding['remediation'] = self.remediation_templates[vuln_type]
        
        # Ensure correlation_id is present
        if 'evidence' in finding and 'correlation_id' not in finding:
            if 'correlation_id' in finding.get('evidence', {}):
                finding['correlation_id'] = finding['evidence']['correlation_id']
            else:
                # Generate a correlation ID if none exists
                import uuid
                finding['correlation_id'] = str(uuid.uuid4())
                if 'evidence' in finding:
                    finding['evidence']['correlation_id'] = finding['correlation_id']
        
        # Track attack chain
        if dependencies:
            self.dependencies[finding_id] = dependencies
            # Build attack chain
            attack_chain = {
                'steps': [],
                'auth_states': [],
                'auth_transitions': [],
                'impact_path': [],
                'transaction_sequence': []
            }
            
            # Add dependent findings to attack chain
            for dep_id in dependencies:
                dep_finding = next((f for f in self.findings if f['id'] == dep_id), None)
                if dep_finding:
                    attack_chain['steps'].append({
                        'finding_id': dep_id,
                        'type': dep_finding['type'],
                        'description': dep_finding['detail'],
                        'timestamp': dep_finding.get('timestamp')
                    })
                    
                    # Track authentication states and transitions
                    if 'auth_state' in dep_finding.get('evidence', {}):
                        auth_state = dep_finding['evidence']['auth_state']
                        attack_chain['auth_states'].append(auth_state)
                        
                        # Add transaction details to sequence
                        if 'login_request' in dep_finding.get('evidence', {}) and 'login_response' in dep_finding.get('evidence', {}):
                            attack_chain['transaction_sequence'].append({
                                'finding_id': dep_id,
                                'request': dep_finding['evidence']['login_request'],
                                'response': dep_finding['evidence']['login_response'],
                                'auth_state': auth_state,
                                'timestamp': dep_finding.get('evidence', {}).get('login_request', {}).get('timestamp')
                            })
                        
                        # Add any other transactions
                        for key in dep_finding.get('evidence', {}):
                            if key.endswith('_request') and key != 'login_request':
                                response_key = key.replace('_request', '_response')
                                if response_key in dep_finding['evidence']:
                                    attack_chain['transaction_sequence'].append({
                                        'finding_id': dep_id,
                                        'request': dep_finding['evidence'][key],
                                        'response': dep_finding['evidence'][response_key],
                                        'auth_state': auth_state,
                                        'timestamp': dep_finding.get('evidence', {}).get(key, {}).get('timestamp')
                                    })
            
            # Add current finding as final step
            attack_chain['steps'].append({
                'finding_id': finding_id,
                'type': finding['type'],
                'description': finding['detail'],
                'timestamp': finding['timestamp']
            })
            
            # Add current finding's auth state and transactions
            if 'auth_state' in finding.get('evidence', {}):
                auth_state = finding['evidence']['auth_state']
                attack_chain['auth_states'].append(auth_state)
                
                # Record auth state transitions
                if len(attack_chain['auth_states']) > 1:
                    prev_state = attack_chain['auth_states'][-2]
                    current_state = auth_state
                    attack_chain['auth_transitions'].append({
                        'from': prev_state,
                        'to': current_state,
                        'timestamp': finding['timestamp']
                    })
                
                # Add transaction details to sequence
                for key in finding.get('evidence', {}):
                    if key.endswith('_request'):
                        response_key = key.replace('_request', '_response')
                        if response_key in finding['evidence']:
                            attack_chain['transaction_sequence'].append({
                                'finding_id': finding_id,
                                'request': finding['evidence'][key],
                                'response': finding['evidence'][response_key],
                                'auth_state': auth_state,
                                'timestamp': finding.get('evidence', {}).get(key, {}).get('timestamp')
                            })
            
            # Store attack chain
            self.attack_chains[finding_id] = attack_chain
            finding['attack_chain'] = attack_chain
            
            # Link related findings
            finding['related_findings'] = []
            for dep_id in dependencies:
                if dep_id in [f['id'] for f in self.findings]:
                    finding['related_findings'].append(dep_id)
        
        self.findings.append(finding)
        self.logger.debug(f"Added finding {finding_id} with {len(dependencies or [])} dependencies")
        return finding_id

    def add_credential(self, username: str, credential_data: Dict[str, Any]) -> None:
        """Store discovered credentials"""
        self.credentials[username] = credential_data
        self.logger.debug(f"Added credentials for user: {username}")

    def add_token(self, token_type: str, token: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Store discovered authentication tokens"""
        if token_type not in self.tokens:
            self.tokens[token_type] = []
        
        token_entry = {
            'token': token,
            'discovered_at': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        self.tokens[token_type].append(token_entry)
        self.logger.debug(f"Added {token_type} token")

    def update_context(self, scanner_name: str, context_data: Dict[str, Any]) -> None:
        """Update context for a specific scanner"""
        if scanner_name not in self.context:
            self.context[scanner_name] = {}
        
        self.context[scanner_name].update(context_data)
        self.logger.debug(f"Updated context for {scanner_name}")

    def get_context(self, scanner_name: str) -> Dict[str, Any]:
        """Get context for a specific scanner"""
        return self.context.get(scanner_name, {})

    def get_credentials(self) -> Dict[str, Dict[str, Any]]:
        """Get all discovered credentials"""
        return self.credentials

    def get_tokens(self, token_type: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Get discovered tokens, optionally filtered by type"""
        if token_type:
            return {token_type: self.tokens.get(token_type, [])}
        return self.tokens

    def get_findings(self, with_dependencies: bool = False) -> List[Dict[str, Any]]:
        """Get all findings with dependencies and attack chains"""
        findings_with_deps = []
        for finding in self.findings:
            finding_copy = finding.copy()
            finding_id = finding_copy['id']
            
            # Add dependency information
            if finding_id in self.dependencies:
                finding_copy['dependencies'] = self.dependencies[finding_id]
            
            # Add attack chain information
            if finding_id in self.attack_chains:
                finding_copy['attack_chain'] = self.attack_chains[finding_id]
            
            findings_with_deps.append(finding_copy)

        return findings_with_deps

    def get_related_findings(self, finding_id: str) -> List[Dict[str, Any]]:
        """Get findings related to a specific finding with attack chain context"""
        related = []
        for finding in self.findings:
            if finding.get('id') == finding_id:
                continue
            if finding_id in self.dependencies.get(finding.get('id', ''), []):
                finding_copy = finding.copy()
                # Add attack chain context if available
                if finding.get('id') in self.attack_chains:
                    finding_copy['attack_chain'] = self.attack_chains[finding.get('id')]
                related.append(finding_copy)
        return related