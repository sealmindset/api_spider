#!/usr/bin/env python3
"""
Enhanced Validation Orchestrator
Provides advanced validation and chain attack detection for security findings
"""

from typing import Dict, List, Optional, Any
import requests
import logging
import uuid
from datetime import datetime
from .utils.logger import setup_scanner_logger

class EnhancedValidationOrchestrator:
    def __init__(self):
        self.logger = setup_scanner_logger("enhanced_validation")
        self.context = {}
        self.findings_cache = {}
        self.attack_chains = []

    async def validate_findings(self, findings: List[Dict], url: str) -> List[Dict]:
        """Validate findings with enhanced detection and chain attack analysis"""
        validated_findings = []
        
        for finding in findings:
            try:
                # Generate unique validation ID
                validation_id = str(uuid.uuid4())
                
                # Validate based on vulnerability type
                if finding['type'] == 'SQL_INJECTION':
                    validated = await self.validate_sqli(finding, url)
                elif finding['type'] in ['JWT_WEAK_KEY', 'JWT_BYPASS']:
                    validated = await self.validate_jwt_vulnerability(finding, url)
                elif finding['type'] == 'UNAUTHORIZED_PASSWORD_CHANGE':
                    validated = await self.validate_password_change(finding, url)
                elif finding['type'] == 'BOLA':
                    validated = await self.validate_bola(finding, url)
                else:
                    validated = finding
                
                if validated:
                    # Add validation metadata
                    validated['validation'] = {
                        'validation_id': validation_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'validation_type': 'enhanced'
                    }
                    validated_findings.append(validated)
                    
                    # Update attack chains
                    await self.update_attack_chains(validated)
                    
            except Exception as e:
                self.logger.error(f"Error validating finding: {str(e)}")
                
        return validated_findings

    async def validate_sqli(self, finding: Dict, url: str) -> Optional[Dict]:
        """Enhanced SQLi validation with multiple techniques"""
        try:
            # Extract original payload and endpoint
            payload = finding['evidence'].get('payload')
            endpoint = finding['evidence'].get('url')
            
            # Additional validation techniques
            validations = [
                self.validate_sqli_time_based(endpoint, payload),
                self.validate_sqli_boolean_based(endpoint, payload),
                self.validate_sqli_error_based(endpoint, payload)
            ]
            
            # Require at least 2 successful validations
            success_count = sum(1 for v in validations if v)
            if success_count >= 2:
                finding['validation_details'] = {
                    'validation_count': success_count,
                    'techniques': ['time_based', 'boolean_based', 'error_based']
                }
                return finding
                
        except Exception as e:
            self.logger.error(f"Error in SQLi validation: {str(e)}")
            
        return None

    async def validate_jwt_vulnerability(self, finding: Dict, url: str) -> Optional[Dict]:
        """Enhanced JWT vulnerability validation"""
        try:
            # Extract token and endpoint
            token = finding['evidence'].get('auth_state', {}).get('token')
            endpoint = finding['evidence'].get('url')
            
            if not token or not endpoint:
                return None
                
            # Validate token manipulation
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.get(endpoint, headers=headers, timeout=5)
            
            if resp.status_code == 200:
                # Additional checks for token structure and claims
                token_parts = token.split('.')
                if len(token_parts) != 3:
                    return None
                    
                finding['validation_details'] = {
                    'token_validated': True,
                    'response_code': resp.status_code
                }
                return finding
                
        except Exception as e:
            self.logger.error(f"Error in JWT validation: {str(e)}")
            
        return None

    async def validate_password_change(self, finding: Dict, url: str) -> Optional[Dict]:
        """Validate unauthorized password change with additional checks"""
        try:
            # Extract credentials and tokens
            auth_state = finding['evidence'].get('auth_state', {})
            original_token = auth_state.get('auth_token')
            
            if not original_token:
                return None
                
            # Verify the impact
            test_credentials = {
                'username': 'test_validation_user',
                'password': 'test_password'
            }
            
            # Try to change password for test user
            headers = {"Authorization": f"Bearer {original_token}"}
            change_resp = requests.put(
                f"{url}/users/v1/{test_credentials['username']}/password",
                headers=headers,
                json={'password': 'new_password'},
                timeout=5
            )
            
            if change_resp.status_code in [200, 204]:
                finding['validation_details'] = {
                    'validation_user': test_credentials['username'],
                    'change_successful': True
                }
                return finding
                
        except Exception as e:
            self.logger.error(f"Error in password change validation: {str(e)}")
            
        return None

    async def validate_bola(self, finding: Dict, url: str) -> Optional[Dict]:
        """Validate BOLA vulnerability with resource enumeration"""
        try:
            # Extract endpoint and auth state
            endpoint = finding['evidence'].get('url')
            auth_state = finding['evidence'].get('auth_state', {})
            
            if not endpoint:
                return None
                
            # Test with different resource IDs
            test_ids = [1, 2, 'admin', str(uuid.uuid4())]
            successful_access = 0
            
            for test_id in test_ids:
                test_url = f"{url}/users/v1/{test_id}"
                headers = {}
                if auth_state.get('token'):
                    headers['Authorization'] = f"Bearer {auth_state['token']}"
                    
                resp = requests.get(test_url, headers=headers, timeout=5)
                if resp.status_code == 200:
                    successful_access += 1
                    
            if successful_access >= 2:
                finding['validation_details'] = {
                    'successful_access_count': successful_access,
                    'test_ids': test_ids
                }
                return finding
                
        except Exception as e:
            self.logger.error(f"Error in BOLA validation: {str(e)}")
            
        return None

    async def update_attack_chains(self, finding: Dict) -> None:
        """Update attack chains based on new findings"""
        try:
            # Get dependencies
            dependencies = finding.get('dependencies', [])
            
            # Create new chain or update existing
            chain = {
                'chain_id': str(uuid.uuid4()),
                'findings': dependencies + [finding],
                'severity': finding['severity'],
                'updated_at': datetime.utcnow().isoformat()
            }
            
            self.attack_chains.append(chain)
            
        except Exception as e:
            self.logger.error(f"Error updating attack chains: {str(e)}")

    def get_attack_chains(self) -> List[Dict]:
        """Get discovered attack chains"""
        return self.attack_chains

    def get_validation_metrics(self) -> Dict:
        """Get metrics about validation results"""
        metrics = {
            'total_findings': len(self.findings_cache),
            'validated_findings': len([f for f in self.findings_cache.values() if f.get('validation')]),
            'attack_chains': len(self.attack_chains)
        }
        return metrics