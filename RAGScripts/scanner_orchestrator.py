#!/usr/bin/env python3

from typing import Dict, List, Optional, Type
from .base_scanner import BaseScanner
from .bola_check import BOLAScanner
from .sqli_check import SQLiScanner
from .xss_check import XSSScanner
from .xxe_check import XXEScanner
from .auth_check import AuthBypassScanner
from .auth_level_check import AuthLevelScanner
from .path_traversal_check import PathTraversalScanner
from .asset_management_check import AssetManagementScanner
from .llm_analyzer import LLMAnalyzer
from .utils.findings_manager import FindingsManager
import logging
import aiohttp

class ScannerOrchestrator:
    def __init__(self):
        self.scanners = [
            BOLAScanner,
            SQLiScanner,
            XSSScanner,
            XXEScanner,
            AuthBypassScanner,
            AuthLevelScanner,
            PathTraversalScanner,
            AssetManagementScanner
        ]
        self.llm_analyzer = LLMAnalyzer()
        self.logger = logging.getLogger(__name__)
        
        # Initialize findings manager for enhanced reporting
        self.findings_manager = FindingsManager(self.logger)
        
        # Initialize validation orchestrator for multi-stage verification
        from RAGScripts.utils.validation_orchestrator import ValidationOrchestrator
        self.validation_orchestrator = ValidationOrchestrator()
        
    async def scan_endpoint(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        """Run all security scanners on a single endpoint with sequential LLM analysis and enhanced reporting"""
        findings = []
        
        for scanner_class in self.scanners:
            try:
                scanner = scanner_class()
                scanner_findings = scanner.scan(url, method, path, response, token)
                
                # Process each finding sequentially with LLM analysis
                llm_validated_findings = []
                for finding in scanner_findings:
                    # Analyze finding with LLM
                    llm_analysis = await self.llm_analyzer.analyze_finding(finding)
                    
                    # Only include findings that LLM validates as true positives
                    if llm_analysis and llm_analysis.get('confidence', 0) > 0.7:
                        finding['llm_analysis'] = llm_analysis
                        
                        # Add finding to findings manager with enhanced reporting
                        finding_id = self.findings_manager.add_finding(
                            finding,
                            dependencies=finding.get('dependencies', [])
                        )
                        
                        # Update finding with any additional context from findings manager
                        finding_context = self.findings_manager.get_context(scanner_class.__name__)
                        if finding_context:
                            finding['context'] = finding_context
                        
                        llm_validated_findings.append(finding)
                
                # Perform multi-stage verification on LLM-validated findings
                validated_findings = await self.validation_orchestrator.validate_findings(llm_validated_findings)
                
                # Add validated findings with attack chain information
                for validated_finding in validated_findings:
                    # Get related findings to build attack chains
                    related = self.findings_manager.get_related_findings(validated_finding.get('id', ''))
                    if related:
                        validated_finding['related_findings'] = related
                    findings.append(validated_finding)
                
            except Exception as e:
                self.logger.error(f"Error running {scanner_class.__name__}: {str(e)}")
                continue
                
        return findings

    async def scan_api(self, base_url: str, endpoints: List[Dict], token: Optional[str] = None) -> List[Dict]:
        """Scan entire API with sequential security checks, LLM analysis, and enhanced reporting"""
        all_findings = []
        
        for endpoint in endpoints:
            url = base_url.rstrip('/') + '/' + endpoint['path'].lstrip('/')
            method = endpoint.get('method', 'GET')
            
            try:
                # Make initial request
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers={'Authorization': f'Bearer {token}'} if token else {}) as response:
                        # Run all scanners on this endpoint sequentially
                        endpoint_findings = await self.scan_endpoint(base_url, method, endpoint['path'], response, token)
                        all_findings.extend(endpoint_findings)
                
            except Exception as e:
                self.logger.error(f"Error scanning endpoint {url}: {str(e)}")
                continue
                
        # Export validation metrics after scan completes
        try:
            metrics_path = "validation_metrics.json"
            self.validation_orchestrator.export_validation_metrics(metrics_path)
            self.logger.info(f"Validation metrics exported to {metrics_path}")
        except Exception as e:
            self.logger.error(f"Failed to export validation metrics: {str(e)}")
            
        # Get final findings with full attack chains and relationships
        final_findings = self.findings_manager.get_findings(with_dependencies=True)
        
        return final_findings