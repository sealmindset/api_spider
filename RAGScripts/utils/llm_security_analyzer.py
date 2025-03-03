#!/usr/bin/env python3

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import logging

class LLMSecurityAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.vulnerability_patterns = {
            'SQLI': ['sql injection', 'database manipulation', 'query injection'],
            'XSS': ['cross-site scripting', 'script injection', 'malicious script'],
            'SSRF': ['server-side request forgery', 'internal service access'],
            'IDOR': ['insecure direct object reference', 'unauthorized access'],
            'AUTH_BYPASS': ['authentication bypass', 'broken auth']
        }

    def analyze_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security findings and generate comprehensive report"""
        try:
            analysis_result = {
                'summary': self._generate_executive_summary(findings),
                'detailed_analysis': self._perform_detailed_analysis(findings),
                'risk_assessment': self._assess_risks(findings),
                'remediation_plan': self._create_remediation_plan(findings),
                'technical_details': self._extract_technical_details(findings),
                'business_impact': self._assess_business_impact(findings),
                'timestamp': datetime.utcnow().isoformat()
            }
            return analysis_result
        except Exception as e:
            self.logger.error(f"Error during findings analysis: {str(e)}")
            return self._generate_fallback_analysis(findings)

    def _generate_executive_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate an executive summary of security findings"""
        try:
            total_findings = len(findings)
            severity_counts = self._count_severity_levels(findings)
            critical_vulns = [f for f in findings if f.get('severity') == 'CRITICAL']
            
            return {
                'total_findings': total_findings,
                'severity_distribution': severity_counts,
                'critical_findings_count': len(critical_vulns),
                'key_risks': self._identify_key_risks(findings),
                'recommendation_summary': self._summarize_recommendations(findings)
            }
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {str(e)}")
            return {'error': 'Failed to generate executive summary'}

    def _perform_detailed_analysis(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform detailed analysis of each finding"""
        detailed_findings = []
        
        for finding in findings:
            try:
                analysis = {
                    'finding_type': finding.get('type'),
                    'severity': finding.get('severity'),
                    'technical_analysis': self._analyze_technical_aspects(finding),
                    'attack_vectors': self._identify_attack_vectors(finding),
                    'evidence_analysis': self._analyze_evidence(finding.get('evidence', {})),
                    'context_analysis': self._analyze_context(finding.get('context', {}))
                }
                detailed_findings.append(analysis)
            except Exception as e:
                self.logger.error(f"Error analyzing finding: {str(e)}")
                continue
                
        return detailed_findings

    def _assess_risks(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall security risks based on findings"""
        risk_assessment = {
            'risk_levels': self._calculate_risk_levels(findings),
            'threat_landscape': self._analyze_threat_landscape(findings),
            'vulnerability_trends': self._identify_vulnerability_trends(findings),
            'attack_surface': self._assess_attack_surface(findings)
        }
        return risk_assessment

    def _create_remediation_plan(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a detailed remediation plan"""
        remediation_plan = {
            'immediate_actions': self._identify_immediate_actions(findings),
            'short_term_fixes': self._identify_short_term_fixes(findings),
            'long_term_solutions': self._identify_long_term_solutions(findings),
            'resource_requirements': self._estimate_resource_requirements(findings)
        }
        return remediation_plan

    def _analyze_technical_aspects(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze technical aspects of a finding"""
        return {
            'vulnerability_type': self._classify_vulnerability(finding),
            'affected_components': self._identify_affected_components(finding),
            'technical_impact': self._assess_technical_impact(finding),
            'exploitation_complexity': self._assess_exploitation_complexity(finding)
        }

    def _analyze_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze evidence provided in the finding"""
        return {
            'request_analysis': self._analyze_request(evidence.get('request', {})),
            'response_analysis': self._analyze_response(evidence.get('response', {})),
            'correlation_analysis': self._analyze_correlations(evidence)
        }

    def _generate_fallback_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate basic analysis when detailed analysis fails"""
        return {
            'summary': {
                'total_findings': len(findings),
                'severity_distribution': self._count_severity_levels(findings)
            },
            'basic_analysis': [{
                'type': f.get('type'),
                'severity': f.get('severity'),
                'description': f.get('detail')
            } for f in findings],
            'timestamp': datetime.utcnow().isoformat()
        }

    def _count_severity_levels(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts

    def _classify_vulnerability(self, finding: Dict[str, Any]) -> str:
        """Classify the type of vulnerability"""
        finding_type = finding.get('type', '').upper()
        for vuln_type, patterns in self.vulnerability_patterns.items():
            if any(pattern in finding.get('detail', '').lower() for pattern in patterns):
                return vuln_type
        return finding_type

    def _identify_key_risks(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify key security risks from findings"""
        critical_high_findings = [f for f in findings if f.get('severity', '').upper() in ['CRITICAL', 'HIGH']]
        return [f"{f.get('type')}: {f.get('detail')}" for f in critical_high_findings[:5]]

    def _summarize_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Summarize key recommendations"""
        recommendations = set()
        for finding in findings:
            if 'remediation' in finding and 'steps' in finding['remediation']:
                recommendations.update(finding['remediation']['steps'])
        return list(recommendations)[:5]