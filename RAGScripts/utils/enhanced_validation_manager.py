import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, UTC
import json
import re
import requests

class EnhancedValidationManager:
    """
    Enhanced validation manager that implements sophisticated multi-stage verification
    techniques based on real-world penetration testing methodologies.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.attack_metrics = {}
        # Updated thresholds based on walkthrough analysis
        self.verification_thresholds = {
            'SQLI': 0.6,  # Lowered from 0.7 to catch more potential SQLi
            'XSS': 0.65,  # Lowered from 0.75 to be more sensitive
            'AUTH_BYPASS': 0.7,  # Lowered from 0.8
            'JWT_BYPASS': 0.7,  # Lowered from 0.8
            'JWT_ALG_NONE': 0.75,  # Lowered from 0.85
            'IDOR': 0.65,  # Lowered from 0.75
            'BOLA': 0.65,  # Lowered from 0.75
            'PATH_TRAVERSAL': 0.6,  # Lowered from 0.7
            'SENSITIVE_DATA': 0.6,  # Lowered from 0.7
            'UNAUTHORIZED_PASSWORD_CHANGE': 0.7,  # Lowered from 0.8
            'MASS_ASSIGNMENT': 0.65,  # Lowered from 0.75
            'USER_ENUM': 0.6,  # Lowered from 0.7
            'REGEX_DOS': 0.7,  # Lowered from 0.8
            'RATE_LIMIT': 0.6,  # Lowered from 0.7
            'CHAIN_ATTACK': 0.8  # Lowered from 0.9 but kept higher for chain attacks
        }
        
        # Initialize validation techniques registry
        self._init_validation_techniques()
        
    def _init_validation_techniques(self):
        """Initialize validation techniques for each vulnerability type"""
        self.validation_techniques = {
            'SQLI': self._verify_sql_injection,
            'AUTH_BYPASS': self._verify_auth_bypass,
            'JWT_BYPASS': self._verify_jwt_bypass,
            'JWT_ALG_NONE': self._verify_jwt_alg_none,
            'IDOR': self._verify_idor,
            'BOLA': self._verify_bola,
            'PATH_TRAVERSAL': self._verify_path_traversal,
            'UNAUTHORIZED_PASSWORD_CHANGE': self._verify_unauthorized_password_change,
            'MASS_ASSIGNMENT': self._verify_mass_assignment,
            'USER_ENUM': self._verify_user_enum,
            'REGEX_DOS': self._verify_regex_dos,
            'RATE_LIMIT': self._verify_rate_limit,
            'CHAIN_ATTACK': self._verify_chain_attack
        }
        
    def verify_vulnerability(self, finding: Dict, response: Optional[Dict] = None, 
                             context: Optional[Dict] = None) -> Dict:
        """Perform multi-stage verification of a potential vulnerability"""
        vuln_type = finding.get('type')
        verification_score = 0.0
        verification_steps = []
        verification_details = {}
        
        # Basic validation checks
        if self._validate_basic_finding(finding):
            verification_score += 0.1  # Reduced from 0.2 to give even more weight to specific checks
            verification_steps.append('basic_validation_passed')
            
        # Perform specific verification based on vulnerability type
        if vuln_type in self.validation_techniques:
            score, steps, details = self.validation_techniques[vuln_type](finding, context)
            verification_score += score
            verification_steps.extend(steps)
            verification_details.update(details)
        else:
            # Generic verification for unknown vulnerability types
            score, steps, details = self._verify_generic(finding)
            verification_score += score
            verification_steps.extend(steps)
            verification_details.update(details)
            
        # Update attack metrics
        threshold = self.verification_thresholds.get(vuln_type, 0.7)
        self._update_metrics(vuln_type, verification_score > threshold)
        
        return {
            'original_finding': finding,
            'verification_score': verification_score,
            'verification_steps': verification_steps,
            'verification_details': verification_details,
            'verified': verification_score > threshold,
            'timestamp': datetime.now(UTC).isoformat()
        }
    
    def _validate_basic_finding(self, finding: Dict) -> bool:
        """Perform basic validation of finding format and data"""
        required_fields = ['type', 'severity', 'detail', 'evidence']
        if not all(field in finding for field in required_fields):
            return False
            
        if 'evidence' not in finding or not isinstance(finding['evidence'], dict):
            return False
            
        return True
    
    def _verify_generic(self, finding: Dict) -> Tuple[float, List[str], Dict]:
        """Generic verification for unknown vulnerability types"""
        score = 0.0
        steps = []
        details = {}
        
        evidence = finding.get('evidence', {})
        
        # Check if there's a status code indicating success
        if evidence.get('status_code') in [200, 201, 202, 204]:
            score += 0.3
            steps.append('successful_response_code')
            
        # Check if there's a response body with meaningful content
        response_body = evidence.get('response', '')
        if response_body and len(response_body) > 10:
            score += 0.2
            steps.append('meaningful_response_body')
            
        return score, steps, details
        
    def _verify_sql_injection(self, finding: Dict, context: Optional[Dict] = None) -> Tuple[float, List[str], Dict]:
        """Verify SQL injection vulnerability with multiple test cases"""
        score = 0.0
        steps = []
        details = {}
        
        evidence = finding.get('evidence', {})
        payload = evidence.get('payload', '')
        response = evidence.get('response', '')
        
        # Check for SQL error patterns (enhanced list from walkthroughs)
        sql_errors = [
            'SQL syntax',
            'ORA-',
            'MySQL',
            'SQLite',
            'PostgreSQL',
            'syntax error',
            'unclosed quotation mark',
            'unterminated string',
            'SQLSTATE',
            'Warning: mysql_',
            'Warning: pg_',
            'function.pg-query',
            'function.mysql-query',
            'driver.sqlsrv',
            'driver.pgsql',
            'driver.mysql',
            'exception.ora',
            'oracle.jdbc',
            'quoted string not properly terminated'
        ]
        if any(error.lower() in response.lower() for error in sql_errors):
            score += 0.3
            steps.append('sql_error_pattern_detected')
            details['detected_errors'] = [error for error in sql_errors if error.lower() in response.lower()]
            
        # Verify boolean-based injection (enhanced from walkthroughs)
        boolean_patterns = ['true', 'false', '1=1', '1=2', 'or 1=1', 'and 1=1']
        if any(pattern in payload.lower() for pattern in boolean_patterns):
            if evidence.get('status_code') in [200, 500]:
                score += 0.2
                steps.append('boolean_based_injection_verified')
                details['boolean_pattern'] = next((pattern for pattern in boolean_patterns if pattern in payload.lower()), None)
                
        # Check for time-based injection indicators
        time_patterns = ['sleep', 'delay', 'pg_sleep', 'waitfor', 'benchmark']
        if any(pattern in payload.lower() for pattern in time_patterns):
            if evidence.get('response_time', 0) > 2:  # Reduced from 5 to 2 seconds based on walkthroughs
                score += 0.2
                steps.append('time_based_injection_verified')
                details['time_pattern'] = next((pattern for pattern in time_patterns if pattern in payload.lower()), None)
                details['response_time'] = evidence.get('response_time', 0)
                
        # Check for UNION-based injection
        if 'union' in payload.lower() and 'select' in payload.lower():
            # Look for data structure changes in response
            if len(response) > 100:  # Arbitrary threshold for a substantial response
                score += 0.2
                steps.append('union_based_injection_possible')
                details['union_payload'] = payload
                
        # Check for data extraction evidence
        data_patterns = ['version()', 'database()', 'user()', 'schema_name', 'table_name']
        if any(pattern in payload.lower() for pattern in data_patterns):
            if any(pattern in response.lower() for pattern in ['mysql', 'postgresql', 'oracle', 'sql server', 'sqlite']):
                score += 0.3
                steps.append('data_extraction_successful')
                details['extracted_data_type'] = next((pattern for pattern in data_patterns if pattern in payload.lower()), None)
                
        return score, steps, details
        
    def _verify_jwt_bypass(self, finding: Dict, context: Optional[Dict] = None) -> Tuple[float, List[str], Dict]:
        """Verify JWT authentication bypass vulnerability"""
        score = 0.0
        steps = []
        details = {}
        
        evidence = finding.get('evidence', {})
        headers = evidence.get('headers', {})
        response = evidence.get('response', '')
        status_code = evidence.get('status_code')
        
        # Check if the attack was successful based on status code
        if status_code in [200, 201, 202, 204]:
            score += 0.3
            steps.append('successful_jwt_bypass')
            details['status_code'] = status_code
            
        # Check for weak key usage
        if 'weak_key' in finding.get('detail', '').lower():
            score += 0.2
            steps.append('weak_key_detected')
            details['weak_key'] = True
            
        # Check for sensitive data in response
        sensitive_patterns = ['user', 'admin', 'role', 'permission', 'email', 'profile']
        found_patterns = [pattern for pattern in sensitive_patterns if pattern in response.lower()]
        if found_patterns:
            score += 0.3
            steps.append('sensitive_data_accessed')
            details['sensitive_data_patterns'] = found_patterns
            
        # Check for token manipulation evidence
        auth_header = headers.get('Authorization', '')
        if auth_header and 'bearer' in auth_header.lower():
            token = auth_header.split(' ')[-1]
            if token:
                # Check for token tampering signs
                if len(token.split('.')) == 3:  # Valid JWT format
                    score += 0.2
                    steps.append('jwt_token_used')
                    details['token_format_valid'] = True
                    
        return score, steps, details
        
    def _verify_jwt_alg_none(self, finding: Dict, context: Optional[Dict] = None) -> Tuple[float, List[str], Dict]:
        """Verify JWT algorithm none attack"""
        score = 0.0
        steps = []
        details = {}
        
        evidence = finding.get('evidence', {})
        auth_state = evidence.get('auth_state', {})
        status_code = evidence.get('status_code', 0)
        
        # Check if the attack was successful
        if status_code in [200, 201, 202, 204]:
            score += 0.4
            steps.append('successful_alg_none_attack')
            details['status_code'] = status_code
            
        # Verify the token has alg:none
        if auth_state.get('attack') == 'alg_none':
            score += 0.3
            steps.append('alg_none_token_verified')
            details['attack_type'] = 'alg_none'
            
        # Check token format
        token = auth_state.get('token', '')
        if token:
            token_parts = token.split('.')
            if len(token_parts) >= 2 and token_parts[-1] == '':  # No signature part
                score += 0.3
                steps.append('signature_missing_verified')
                details['token_parts'] = len(token_parts)
                
        return score, steps, details
        
    def _verify_bola(self, finding: Dict, context: Optional[Dict] = None) -> Tuple[float, List[str], Dict]:
        """Verify Broken Object Level Authorization vulnerability"""
        score = 0.0
        steps = []
        details = {}
        
        evidence = finding.get('evidence', {})
        url = evidence.get('url', '')
        status_code = evidence.get('status_code', 0)
        response = evidence.get('response', '')
        
        # Check if unauthorized resource access was successful
        if status_code == 200:
            score += 0.3
            steps.append('successful_resource_access')
            details['status_code'] = status_code
            
        # Check if URL contains an ID parameter
        id_patterns = [r'/\d+/', r'id=\d+', r'user(id|_id)=\d+', r'account(id|_id)=\d+']
        if any(re.search(pattern, url) for pattern in id_patterns):
            score += 0.2
            steps.append('id_parameter_detected')
            details['id_in_url'] = True
            
        # Check if different user's data was accessed
        user_data_patterns = ['username', 'email', 'profile', 'account', 'user_id']
        if any(pattern in response.lower() for pattern in user_data_patterns):
            score += 0.3
            steps.append('user_data_accessed')
            details['data_patterns'] = [p for p in user_data_patterns if p in response.lower()]
            
        # Check if the response contains data that should be protected
        sensitive_data_patterns = ['password', 'token', 'secret', 'key', 'credit', 'ssn', 'social']
        if any(pattern in response.lower() for pattern in sensitive_data_patterns):
            score += 0.2
            steps.append('sensitive_data_exposed')
            details['sensitive_patterns'] = [p for p in sensitive_data_patterns if p in response.lower()]