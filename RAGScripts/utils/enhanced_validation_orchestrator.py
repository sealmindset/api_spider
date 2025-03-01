import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from .enhanced_validation_manager import EnhancedValidationManager

class EnhancedValidationOrchestrator:
    """
    Enhanced validation orchestrator that implements sophisticated validation techniques
    based on real-world penetration testing methodologies and chain attack detection.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.validation_manager = EnhancedValidationManager()
        self.chain_attacks = {
            'sqli_chain': ['SQLI', 'PRIVILEGE_ESCALATION', 'MASS_ASSIGNMENT'],
            'jwt_chain': ['JWT_BYPASS', 'BOLA', 'UNAUTHORIZED_PASSWORD_CHANGE'],
            'user_chain': ['USER_ENUM', 'PASSWORD_SPRAY', 'ACCOUNT_TAKEOVER']
        }
        
    async def validate_findings(self, findings: List[Dict], context: Optional[Dict] = None) -> List[Dict]:
        """Process a list of findings through enhanced validation steps"""
        validated_findings = []
        potential_chains = {}
        
        # First pass: Validate individual findings
        for finding in findings:
            try:
                # Perform multi-stage verification with context
                validation_result = self.validation_manager.verify_vulnerability(
                    finding,
                    context=context
                )
                
                if validation_result.get('verified', False):
                    # Add validation data to the finding
                    finding['validation'] = {
                        'score': validation_result.get('verification_score'),
                        'steps': validation_result.get('verification_steps'),
                        'details': validation_result.get('verification_details'),
                        'timestamp': validation_result.get('timestamp')
                    }
                    validated_findings.append(finding)
                    
                    # Track potential chain attacks
                    vuln_type = finding.get('type')
                    for chain_name, chain_steps in self.chain_attacks.items():
                        if vuln_type in chain_steps:
                            if chain_name not in potential_chains:
                                potential_chains[chain_name] = []
                            potential_chains[chain_name].append(finding)
                else:
                    self.logger.info(
                        f"Finding rejected: {finding.get('type')} - "
                        f"Score: {validation_result.get('verification_score')}"
                    )
            except Exception as e:
                self.logger.error(f"Error validating finding: {str(e)}")
                continue
        
        # Second pass: Validate chain attacks
        chain_findings = await self._validate_chain_attacks(potential_chains, context)
        if chain_findings:
            validated_findings.extend(chain_findings)
        
        return validated_findings
    
    async def _validate_chain_attacks(self, potential_chains: Dict[str, List[Dict]], 
                                     context: Optional[Dict] = None) -> List[Dict]:
        """Validate potential chain attacks identified during initial validation"""
        chain_findings = []
        
        for chain_name, chain_findings_list in potential_chains.items():
            try:
                # Check if we have all required steps for this chain
                chain_steps = self.chain_attacks[chain_name]
                found_steps = [f.get('type') for f in chain_findings_list]
                
                # Verify if all required steps are present in the correct order
                if all(step in found_steps for step in chain_steps):
                    # Create chain attack finding
                    chain_finding = {
                        'type': 'CHAIN_ATTACK',
                        'severity': 'CRITICAL',
                        'detail': f'Detected complete {chain_name} attack chain',
                        'chain_name': chain_name,
                        'chain_steps': chain_steps,
                        'evidence': {
                            'component_findings': [
                                {
                                    'type': f.get('type'),
                                    'validation_score': f.get('validation', {}).get('score'),
                                    'evidence': f.get('evidence')
                                } for f in chain_findings_list
                            ],
                            'timestamp': datetime.utcnow().isoformat()
                        }
                    }
                    
                    # Validate the chain attack finding
                    validation_result = self.validation_manager.verify_vulnerability(
                        chain_finding,
                        context=context
                    )
                    
                    if validation_result.get('verified', False):
                        chain_finding['validation'] = {
                            'score': validation_result.get('verification_score'),
                            'steps': validation_result.get('verification_steps'),
                            'details': validation_result.get('verification_details'),
                            'timestamp': validation_result.get('timestamp')
                        }
                        chain_findings.append(chain_finding)
                        
            except Exception as e:
                self.logger.error(f"Error validating chain attack {chain_name}: {str(e)}")
                continue
        
        return chain_findings
    
    def get_validation_metrics(self) -> Dict:
        """Get metrics on validation success rates by vulnerability type"""
        return self.validation_manager.get_attack_metrics()
    
    def export_validation_metrics(self, file_path: str) -> None:
        """Export validation metrics to a file"""
        self.validation_manager.export_metrics(file_path)