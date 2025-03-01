#!/usr/bin/env python3

import asyncio
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
import requests

from .smart_scanner_orchestrator import SmartScannerOrchestrator
from .utils.logger import setup_logger
from .base_scanner import BaseScanner

# Import scanner classes
from .RAG_SQLi import SQLiScanner
from .RAG_BOLA import BOLAScanner
from .RAG_unauthorized_password_change import UnauthorizedPasswordChangeScanner
from .RAG_MassAssign import MassAssignmentScanner
from .RAG_Leak import DataExposureScanner
from .RAG_UserPass import UserPassEnumScanner
from .RAG_RegexDoS import RegexDOSScanner
from .RAG_Rate import RateLimitScanner
from .RAG_jwt_bypass import JWTBypassScanner

class SmartAPISecurityScanner:
    """Enhanced API security scanner that uses the SmartScannerOrchestrator
    for dependency tracking, credential sharing, and context maintenance"""
    
    def __init__(self, target_url: str, token: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.target_url = target_url
        self.logger = logger or setup_logger("smart_api_scanner")
        self.token = token
        self.headers = {}
        
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        
        # Initialize the smart scanner orchestrator
        self.orchestrator = SmartScannerOrchestrator(self.logger)
        
        # Register security scanners
        self._register_scanners()
        
    def _register_scanners(self):
        """Register all security scanners with the orchestrator"""
        scanners = [
            SQLiScanner,
            BOLAScanner,
            UnauthorizedPasswordChangeScanner,
            MassAssignmentScanner,
            DataExposureScanner,
            UserPassEnumScanner,
            RegexDOSScanner,
            RateLimitScanner,
            JWTBypassScanner
        ]
        
        for scanner_class in scanners:
            self.orchestrator.register_scanner(scanner_class)
            
        self.logger.info(f"Registered {len(scanners)} security scanners")
    
    async def scan_endpoint(self, path: str, method: str = "GET") -> List[Dict]:
        """Scan a single API endpoint with all registered scanners"""
        endpoint_url = urljoin(self.target_url, path)
        self.logger.info(f"Scanning endpoint: {method} {endpoint_url}")
        
        try:
            # Make initial request to the endpoint
            response = requests.request(method, endpoint_url, headers=self.headers)
            
            # Execute smart scanning with dependency tracking and context sharing
            findings = await self.orchestrator.scan_endpoint(
                endpoint_url,
                method,
                path,
                response,
                token=self.token
            )
            
            self.logger.info(f"Found {len(findings)} potential vulnerabilities in {endpoint_url}")
            return findings
            
        except requests.RequestException as e:
            self.logger.error(f"Error accessing {endpoint_url}: {str(e)}")
            return []
    
    async def scan_api(self, endpoints: List[Dict[str, str]]) -> List[Dict]:
        """Scan multiple API endpoints"""
        all_findings = []
        
        for endpoint in endpoints:
            path = endpoint.get('path', '')
            method = endpoint.get('method', 'GET')
            
            findings = await self.scan_endpoint(path, method)
            all_findings.extend(findings)
        
        # Get attack chains after all scans are complete
        attack_chains = self.orchestrator.get_attack_chains()
        self.logger.info(f"Identified {len(attack_chains)} attack chains across endpoints")
        
        return all_findings
    
    def get_attack_chains(self) -> List[Dict]:
        """Get all discovered attack chains with dependencies"""
        return self.orchestrator.get_attack_chains()

# Example usage
async def main():
    scanner = SmartAPISecurityScanner("https://api.example.com")
    
    # Define endpoints to scan
    endpoints = [
        {"path": "/users", "method": "GET"},
        {"path": "/users/login", "method": "POST"},
        {"path": "/admin/settings", "method": "GET"}
    ]
    
    # Run the scan
    findings = await scanner.scan_api(endpoints)
    
    # Get attack chains
    attack_chains = scanner.get_attack_chains()
    
    print(f"Found {len(findings)} vulnerabilities")
    print(f"Identified {len(attack_chains)} attack chains")

if __name__ == "__main__":
    asyncio.run(main())