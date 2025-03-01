import logging
from typing import Dict, List, Optional
from .validation_manager import ValidationManager

class ValidationOrchestrator:
    """Orchestrates the validation process for potential vulnerabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.validation_manager = ValidationManager()
        
    async def validate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Process a list of findings through validation steps"""
        validated_findings = []
        
        for finding in findings:
            try:
                # Perform multi-stage verification
                validation_result = self.validation_manager.verify_vulnerability(finding)
                
                # Only include findings that pass verification threshold
                if validation_result.get('verified', False):
                    # Add validation data to the finding
                    finding['validation'] = {
                        'score': validation_result.get('verification_score'),
                        'steps': validation_result.get('verification_steps'),
                        'timestamp': validation_result.get('timestamp')
                    }
                    validated_findings.append(finding)
                else:
                    self.logger.info(f"Finding rejected: {finding.get('type')} - Score: {validation_result.get('verification_score')}")
            except Exception as e:
                self.logger.error(f"Error validating finding: {str(e)}")
                continue
                
        return validated_findings
    
    def get_validation_metrics(self) -> Dict:
        """Get metrics on validation success rates by vulnerability type"""
        return self.validation_manager.get_attack_metrics()
    
    def export_validation_metrics(self, file_path: str) -> None:
        """Export validation metrics to a file"""
        self.validation_manager.export_metrics(file_path)