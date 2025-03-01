#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import requests
from .base_scanner import BaseScanner
from .utils.findings_manager import FindingsManager
from .utils.logger import setup_logger
from .llm_analyzer import LLMAnalyzer

class SmartScannerOrchestrator:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or setup_logger("smart_scanner_orchestrator")
        self.findings_manager = FindingsManager(self.logger)
        self.llm_analyzer = LLMAnalyzer()
        self.context = {}
        self.scanners = []
        
    def register_scanner(self, scanner_class: type) -> None:
        """Register a security scanner class"""
        if issubclass(scanner_class, BaseScanner):
            self.scanners.append(scanner_class)
            self.logger.debug(f"Registered scanner: {scanner_class.__name__}")
    
    async def scan_endpoint(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        """Execute smart scanning with dependency tracking and context sharing"""
        findings = []
        
        # Initialize scan context
        scan_context = {
            'correlation_id': str(uuid.uuid4()),
            'scan_start': datetime.utcnow().isoformat(),
            'tokens': {},
            'credentials': [],
            'finding_ids': [],
            'auth_states': []
        }
        
        for scanner_class in self.scanners:
            try:
                scanner = scanner_class()
                
                # Get existing context and tokens
                scanner_context = self.findings_manager.get_context(scanner_class.__name__)
                available_tokens = self.findings_manager.get_tokens()
                
                # Update scan context with previous findings
                scan_context.update({
                    'previous_findings': self.findings_manager.get_findings(),
                    'tokens': available_tokens
                })
                
                # Execute scanner with shared context
                scanner_findings = scanner.scan(
                    url,
                    method, 
                    path,
                    response,
                    token=token,
                    tokens=available_tokens,
                    context=scan_context
                )
                
                for finding in scanner_findings:
                    # Analyze finding with LLM
                    llm_analysis = await self.llm_analyzer.analyze_finding(finding)
                    
                    if llm_analysis and llm_analysis.get('confidence', 0) > 0.7:
                        finding['llm_analysis'] = llm_analysis
                        
                        # Add finding with dependency tracking
                        finding_id = self.findings_manager.add_finding(
                            finding,
                            dependencies=finding.get('dependencies', [])
                        )
                        
                        # Update scan context
                        scan_context['finding_ids'].append(finding_id)
                        
                        # Extract and store discovered credentials/tokens
                        if 'discovered_credentials' in finding.get('evidence', {}):
                            for cred in finding['evidence']['discovered_credentials']:
                                self.findings_manager.add_credential(
                                    cred.get('username'),
                                    cred
                                )
                                scan_context['credentials'].append(cred)
                                
                        if 'discovered_tokens' in finding.get('evidence', {}):
                            for token_info in finding['evidence']['discovered_tokens']:
                                self.findings_manager.add_token(
                                    token_info.get('type', 'unknown'),
                                    token_info.get('token'),
                                    token_info.get('metadata')
                                )
                        
                        # Update scanner context
                        if 'context_update' in finding:
                            self.findings_manager.update_context(
                                scanner_class.__name__,
                                finding['context_update']
                            )
                        
                        findings.append(finding)
                
            except Exception as e:
                self.logger.error(f"Error in {scanner_class.__name__}: {str(e)}")
                continue
                
        return findings
    
    def get_attack_chains(self) -> List[Dict]:
        """Get all discovered attack chains with dependencies"""
        findings = self.findings_manager.get_findings(with_dependencies=True)
        attack_chains = []
        
        for finding in findings:
            if 'attack_chain' in finding:
                attack_chains.append({
                    'finding_id': finding['id'],
                    'type': finding['type'],
                    'chain': finding['attack_chain'],
                    'related_findings': self.findings_manager.get_related_findings(finding['id'])
                })
                
        return attack_chains