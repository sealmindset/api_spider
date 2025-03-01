import logging
from typing import Dict, List, Optional
from datetime import datetime, UTC
import json

class ValidationManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.attack_metrics = {}
        self.verification_thresholds = {
            'SQLI': 0.8,
            'XSS': 0.75,
            'AUTH_BYPASS': 0.9,
            'IDOR': 0.85,
            'PATH_TRAVERSAL': 0.8,
            'SENSITIVE_DATA': 0.7
        }
        
    def verify_vulnerability(self, finding: Dict, response: Optional[Dict] = None) -> Dict:
        """Perform multi-stage verification of a potential vulnerability"""
        vuln_type = finding.get('type')
        verification_score = 0.0
        verification_steps = []
        
        # Basic validation checks
        if self._validate_basic_finding(finding):
            verification_score += 0.3
            verification_steps.append('basic_validation_passed')
            
        # Perform specific verification based on vulnerability type
        if vuln_type == 'SQLI':
            score, steps = self._verify_sql_injection(finding)
            verification_score += score
            verification_steps.extend(steps)
            
        elif vuln_type == 'AUTH_BYPASS':
            score, steps = self._verify_auth_bypass(finding)
            verification_score += score
            verification_steps.extend(steps)
            
        elif vuln_type == 'IDOR':
            score, steps = self._verify_idor(finding)
            verification_score += score
            verification_steps.extend(steps)
            
        # Update attack metrics
        self._update_metrics(vuln_type, verification_score > self.verification_thresholds.get(vuln_type, 0.7))
        
        return {
            'original_finding': finding,
            'verification_score': verification_score,
            'verification_steps': verification_steps,
            'verified': verification_score > self.verification_thresholds.get(vuln_type, 0.7),
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
        
    def _verify_sql_injection(self, finding: Dict) -> tuple[float, List[str]]:
        """Verify SQL injection vulnerability with multiple test cases"""
        score = 0.0
        steps = []
        
        evidence = finding.get('evidence', {})
        payload = evidence.get('payload', '')
        response = evidence.get('response', '')
        
        # Check for SQL error patterns
        sql_errors = [
            'SQL syntax',
            'ORA-',
            'MySQL',
            'SQLite',
            'PostgreSQL'
        ]
        if any(error in response for error in sql_errors):
            score += 0.3
            steps.append('sql_error_pattern_detected')
            
        # Verify boolean-based injection
        if 'true' in payload.lower() or 'false' in payload.lower():
            if evidence.get('status_code') in [200, 500]:
                score += 0.2
                steps.append('boolean_based_injection_verified')
                
        # Check for time-based injection indicators
        if 'sleep' in payload.lower() or 'delay' in payload.lower():
            if evidence.get('response_time', 0) > 5:
                score += 0.2
                steps.append('time_based_injection_verified')
                
        return score, steps
        
    def _verify_auth_bypass(self, finding: Dict) -> tuple[float, List[str]]:
        """Verify authentication bypass vulnerability"""
        score = 0.0
        steps = []
        
        evidence = finding.get('evidence', {})
        status_code = evidence.get('status_code')
        headers = evidence.get('headers', {})
        
        # Check if unauthorized access was successful
        if status_code in [200, 201, 202]:
            score += 0.4
            steps.append('successful_unauthorized_access')
            
        # Verify if authentication headers were manipulated
        if 'Authorization' in headers:
            score += 0.3
            steps.append('auth_header_manipulation_detected')
            
        # Check for sensitive data in response
        response_body = evidence.get('response', '')
        sensitive_patterns = ['user', 'admin', 'token', 'key']
        if any(pattern in response_body.lower() for pattern in sensitive_patterns):
            score += 0.3
            steps.append('sensitive_data_in_response')
            
        return score, steps
        
    def _verify_idor(self, finding: Dict) -> tuple[float, List[str]]:
        """Verify Insecure Direct Object Reference vulnerability"""
        score = 0.0
        steps = []
        
        evidence = finding.get('evidence', {})
        test_id = evidence.get('test_id')
        response = evidence.get('response', '')
        
        # Verify if unauthorized resource access was successful
        if evidence.get('status_code') == 200:
            score += 0.4
            steps.append('successful_resource_access')
            
        # Check if different user's data was accessed
        if test_id and test_id in response:
            score += 0.3
            steps.append('different_user_data_accessed')
            
        # Look for sensitive data patterns
        sensitive_patterns = ['id', 'user', 'email', 'account']
        if any(pattern in response.lower() for pattern in sensitive_patterns):
            score += 0.3
            steps.append('sensitive_data_exposure')
            
        return score, steps
        
    def _update_metrics(self, vuln_type: str, success: bool) -> None:
        """Update attack vector success metrics"""
        if vuln_type not in self.attack_metrics:
            self.attack_metrics[vuln_type] = {
                'attempts': 0,
                'successes': 0,
                'success_rate': 0.0,
                'last_updated': None
            }
            
        metrics = self.attack_metrics[vuln_type]
        metrics['attempts'] += 1
        if success:
            metrics['successes'] += 1
        metrics['success_rate'] = metrics['successes'] / metrics['attempts']
        metrics['last_updated'] = datetime.now(UTC).isoformat()
        
    def get_attack_metrics(self) -> Dict:
        """Get current attack vector success metrics"""
        return self.attack_metrics
        
    def export_metrics(self, file_path: str) -> None:
        """Export attack metrics to JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.attack_metrics, f, indent=2)
            self.logger.info(f"Exported attack metrics to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {str(e)}")