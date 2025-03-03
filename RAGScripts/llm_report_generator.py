#!/usr/bin/env python3

from typing import Dict, List, Any, Optional
import json
import logging
from datetime import datetime
from RAGScripts.utils.llm_security_analyzer import LLMSecurityAnalyzer

class LLMReportGenerator:
    """
    LLM-powered report generator that enhances security findings with detailed analysis,
    remediation recommendations, and executive summaries.
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_analyzer = LLMSecurityAnalyzer()
        self.report_templates = {
            'executive': 'executive_summary_template.md',
            'technical': 'technical_report_template.md',
            'remediation': 'remediation_plan_template.md'
        }
        
    def generate_report(self, findings: List[Dict[str, Any]], report_type: str = 'full') -> Dict[str, Any]:
        """
        Generate a comprehensive security report based on findings
        
        Args:
            findings: List of security findings from scanners
            report_type: Type of report to generate ('full', 'executive', 'technical', 'remediation')
            
        Returns:
            Dict containing the generated report
        """
        try:
            # Analyze findings using LLM Security Analyzer
            analysis = self.security_analyzer.analyze_findings(findings)
            
            # Generate appropriate report based on type
            if report_type == 'executive':
                return self._generate_executive_report(findings, analysis)
            elif report_type == 'technical':
                return self._generate_technical_report(findings, analysis)
            elif report_type == 'remediation':
                return self._generate_remediation_report(findings, analysis)
            else:  # full report
                return self._generate_full_report(findings, analysis)
                
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return self._generate_fallback_report(findings)
    
    def _generate_executive_report(self, findings: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an executive summary report focused on business impact and high-level risks
        """
        try:
            # Extract relevant information from analysis
            summary = analysis.get('summary', {})
            risk_assessment = analysis.get('risk_assessment', {})
            business_impact = analysis.get('business_impact', {})
            
            # Create executive report structure
            executive_report = {
                'title': 'API Security Assessment - Executive Summary',
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'overview': {
                    'total_findings': summary.get('total_findings', 0),
                    'severity_distribution': summary.get('severity_distribution', {}),
                    'critical_findings_count': summary.get('critical_findings_count', 0)
                },
                'key_risks': summary.get('key_risks', []),
                'business_impact': business_impact,
                'recommendation_summary': summary.get('recommendation_summary', []),
                'risk_levels': risk_assessment.get('risk_levels', {})
            }
            
            return executive_report
            
        except Exception as e:
            self.logger.error(f"Error generating executive report: {str(e)}")
            return {'error': 'Failed to generate executive report', 'timestamp': datetime.utcnow().isoformat()}
    
    def _generate_technical_report(self, findings: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a detailed technical report with vulnerability details and evidence
        """
        try:
            # Extract relevant information from analysis
            detailed_analysis = analysis.get('detailed_analysis', [])
            technical_details = analysis.get('technical_details', {})
            
            # Create technical report structure
            technical_report = {
                'title': 'API Security Assessment - Technical Report',
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'findings': self._enhance_findings_with_analysis(findings, detailed_analysis),
                'technical_details': technical_details,
                'methodology': self._generate_methodology_section(),
                'tools_used': self._extract_tools_used(findings)
            }
            
            return technical_report
            
        except Exception as e:
            self.logger.error(f"Error generating technical report: {str(e)}")
            return {'error': 'Failed to generate technical report', 'timestamp': datetime.utcnow().isoformat()}
    
    def _generate_remediation_report(self, findings: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a remediation-focused report with detailed fix recommendations
        """
        try:
            # Extract relevant information from analysis
            remediation_plan = analysis.get('remediation_plan', {})
            
            # Create remediation report structure
            remediation_report = {
                'title': 'API Security Assessment - Remediation Plan',
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'immediate_actions': remediation_plan.get('immediate_actions', []),
                'short_term_fixes': remediation_plan.get('short_term_fixes', []),
                'long_term_solutions': remediation_plan.get('long_term_solutions', []),
                'resource_requirements': remediation_plan.get('resource_requirements', {}),
                'finding_specific_remediation': self._extract_finding_specific_remediation(findings)
            }
            
            return remediation_report
            
        except Exception as e:
            self.logger.error(f"Error generating remediation report: {str(e)}")
            return {'error': 'Failed to generate remediation report', 'timestamp': datetime.utcnow().isoformat()}
    
    def _generate_full_report(self, findings: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive report containing executive, technical, and remediation sections
        """
        try:
            # Generate all report sections
            executive_report = self._generate_executive_report(findings, analysis)
            technical_report = self._generate_technical_report(findings, analysis)
            remediation_report = self._generate_remediation_report(findings, analysis)
            
            # Combine into full report
            full_report = {
                'title': 'API Security Assessment - Comprehensive Report',
                'date': datetime.utcnow().strftime('%Y-%m-%d'),
                'executive_summary': executive_report,
                'technical_details': technical_report,
                'remediation_plan': remediation_report,
                'appendices': self._generate_appendices(findings, analysis)
            }
            
            return full_report
            
        except Exception as e:
            self.logger.error(f"Error generating full report: {str(e)}")
            return self._generate_fallback_report(findings)
    
    def _generate_fallback_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a basic report when detailed analysis fails
        """
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
                
        return {
            'title': 'API Security Assessment Report',
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'summary': {
                'total_findings': len(findings),
                'severity_distribution': severity_counts
            },
            'findings': [{
                'type': f.get('type'),
                'severity': f.get('severity'),
                'description': f.get('detail'),
                'remediation': f.get('remediation', {})
            } for f in findings],
            'generated_by': 'LLM Report Generator (Fallback Mode)',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _enhance_findings_with_analysis(self, findings: List[Dict[str, Any]], detailed_analysis: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhance raw findings with detailed analysis information
        """
        enhanced_findings = []
        
        # Create a mapping of finding types to their analysis
        analysis_map = {}
        for analysis in detailed_analysis:
            finding_type = analysis.get('finding_type')
            if finding_type:
                if finding_type not in analysis_map:
                    analysis_map[finding_type] = []
                analysis_map[finding_type].append(analysis)
        
        # Enhance each finding with its corresponding analysis
        for finding in findings:
            finding_type = finding.get('type')
            enhanced_finding = finding.copy()
            
            if finding_type in analysis_map and analysis_map[finding_type]:
                # Get the first matching analysis (could be improved to find best match)
                analysis = analysis_map[finding_type][0]
                enhanced_finding['technical_analysis'] = analysis.get('technical_analysis', {})
                enhanced_finding['attack_vectors'] = analysis.get('attack_vectors', [])
                enhanced_finding['evidence_analysis'] = analysis.get('evidence_analysis', {})
            
            enhanced_findings.append(enhanced_finding)
            
        return enhanced_findings
    
    def _extract_finding_specific_remediation(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract remediation steps specific to each finding
        """
        remediation_steps = []
        
        for finding in findings:
            if 'remediation' in finding:
                remediation_steps.append({
                    'finding_type': finding.get('type'),
                    'severity': finding.get('severity'),
                    'description': finding.get('detail'),
                    'remediation': finding.get('remediation')
                })
                
        return remediation_steps
    
    def _generate_methodology_section(self) -> Dict[str, Any]:
        """
        Generate a section describing the assessment methodology
        """
        return {
            'approach': 'The API security assessment was conducted using a combination of automated scanning and manual verification techniques.',
            'phases': [
                'Reconnaissance and API discovery',
                'Authentication and authorization testing',
                'Input validation and injection testing',
                'Business logic testing',
                'Data validation and verification'
            ],
            'standards': [
                'OWASP API Security Top 10',
                'NIST Cybersecurity Framework',
                'CWE/SANS Top 25'
            ]
        }
    
    def _extract_tools_used(self, findings: List[Dict[str, Any]]) -> List[str]:
        """
        Extract information about tools used in the assessment
        """
        tools = set()
        
        for finding in findings:
            if 'scanner' in finding:
                tools.add(finding['scanner'])
                
        return list(tools) if tools else ['API Spider', 'Custom Security Scanners']
    
    def _generate_appendices(self, findings: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate appendices with additional information
        """
        return {
            'raw_findings': findings,
            'glossary': self._generate_glossary(),
            'references': self._generate_references(),
            'methodology_details': self._generate_detailed_methodology()
        }
    
    def _generate_glossary(self) -> Dict[str, str]:
        """
        Generate a glossary of security terms
        """
        return {
            'API': 'Application Programming Interface - a set of rules that allow programs to talk to each other',
            'BOLA': 'Broken Object Level Authorization - when API endpoints fail to properly check if the requester has permission to access a resource',
            'IDOR': 'Insecure Direct Object Reference - a type of access control vulnerability',
            'JWT': 'JSON Web Token - a compact, URL-safe means of representing claims to be transferred between two parties',
            'OWASP': 'Open Web Application Security Project - a nonprofit foundation that works to improve software security',
            'SQLi': 'SQL Injection - a code injection technique used to attack data-driven applications',
            'XSS': 'Cross-Site Scripting - a type of security vulnerability typically found in web applications'
        }
    
    def _generate_references(self) -> List[Dict[str, str]]:
        """
        Generate references to security standards and resources
        """
        return [
            {
                'title': 'OWASP API Security Top 10',
                'url': 'https://owasp.org/API-Security/editions/2023/en/0x00-header/'
            },
            {
                'title': 'NIST Cybersecurity Framework',
                'url': 'https://www.nist.gov/cyberframework'
            },
            {
                'title': 'CWE/SANS Top 25 Most Dangerous Software Errors',
                'url': 'https://cwe.mitre.org/top25/'
            }
        ]
    
    def _generate_detailed_methodology(self) -> Dict[str, Any]:
        """
        Generate detailed methodology information
        """
        return {
            'reconnaissance': {
                'description': 'Identifying API endpoints and understanding the API structure',
                'techniques': ['Endpoint discovery', 'Parameter analysis', 'Documentation review']
            },
            'authentication_testing': {
                'description': 'Testing authentication mechanisms for weaknesses',
                'techniques': ['Token analysis', 'Session management testing', 'OAuth flow testing']
            },
            'authorization_testing': {
                'description': 'Testing authorization controls and access restrictions',
                'techniques': ['BOLA testing', 'Privilege escalation testing', 'Role-based access control testing']
            },
            'injection_testing': {
                'description': 'Testing for injection vulnerabilities',
                'techniques': ['SQL injection', 'Command injection', 'NoSQL injection']
            },
            'business_logic_testing': {
                'description': 'Testing the business logic of the API',
                'techniques': ['Workflow bypass', 'Business rule testing', 'Logic flaw identification']
            }
        }

# Example usage
if __name__ == "__main