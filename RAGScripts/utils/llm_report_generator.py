#!/usr/bin/env python3

import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from ..llm_analyzer import LLMAnalyzer

class LLMReportGenerator:
    def __init__(self, model_name='llama3.3', timeout=30):
        self.llm_analyzer = LLMAnalyzer(model_name=model_name, timeout=timeout)
        self.logger = logging.getLogger('llm_report_generator')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def analyze_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed vulnerability analysis using LLM while preserving technical evidence."""
        try:
            # Preserve original technical evidence
            technical_evidence = finding.get('evidence', {})
            
            # Prepare context for enhanced LLM analysis
            context = {
                'vulnerability_type': finding.get('type'),
                'severity': finding.get('severity'),
                'finding_details': finding.get('detail'),
                'timestamp': datetime.utcnow().isoformat()
            }

            # Generate enhanced analysis prompt
            analysis_prompt = f"""Provide a comprehensive security analysis for the following vulnerability:
            Type: {finding.get('type')}
            Severity: {finding.get('severity')}
            Details: {finding.get('detail')}

            Please provide:
            1. Root Cause Analysis
            - What are the underlying security weaknesses?
            - Which security controls are missing or ineffective?
            
            2. Business Impact Assessment
            - What are the potential consequences for the organization?
            - How could this vulnerability affect business operations?
            - What data or assets are at risk?
            
            3. Attack Scenario Analysis
            - How might an attacker exploit this vulnerability?
            - What are the potential attack chains?
            - What conditions are required for successful exploitation?
            
            4. Risk Factors
            - What factors increase or decrease the risk?
            - Are there any mitigating circumstances?
            - What is the likelihood of exploitation?
            
            5. Strategic Remediation Guidance
            - What are the immediate mitigation steps?
            - What long-term security improvements are needed?
            - How can similar vulnerabilities be prevented?"""

            # Get enhanced LLM analysis
            analysis_result = self.llm_analyzer.analyze(analysis_prompt, context)

            # Combine enhanced analysis with preserved technical evidence
            return {
                'enhanced_analysis': analysis_result,
                'technical_evidence': technical_evidence,  # Preserve original evidence
                'generated_at': datetime.utcnow().isoformat(),
                'model_used': self.llm_analyzer.model_name
            }

        except Exception as e:
            self.logger.error(f"Error generating LLM analysis: {str(e)}")
            return self._generate_fallback_analysis(finding)

    def generate_executive_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Generate an enhanced executive summary focusing on business impact and risk assessment."""
        try:
            # Prepare comprehensive summary context
            summary_stats = {
                'total_findings': len(findings),
                'severity_counts': self._count_severities(findings),
                'unique_vuln_types': len(set(f.get('type') for f in findings)),
                'critical_findings': [f for f in findings if f.get('severity') == 'CRITICAL'],
                'high_findings': [f for f in findings if f.get('severity') == 'HIGH']
            }

            # Generate enhanced summary prompt
            summary_prompt = f"""Generate a comprehensive executive summary for this security assessment:

            Assessment Overview:
            - Total Findings: {summary_stats['total_findings']}
            - Severity Distribution: {summary_stats['severity_counts']}
            - Unique Vulnerability Types: {summary_stats['unique_vuln_types']}
            - Critical Findings: {len(summary_stats['critical_findings'])}
            - High-Risk Findings: {len(summary_stats['high_findings'])}

            Please provide:
            1. Executive Overview
            - What are the most significant security risks identified?
            - What is the overall security posture?
            - What are the immediate concerns requiring attention?

            2. Business Risk Assessment
            - How do these vulnerabilities impact business operations?
            - What are the potential financial and reputational risks?
            - What regulatory compliance issues are involved?

            3. Strategic Recommendations
            - What are the top priority remediation actions?
            - What strategic security improvements are needed?
            - What is the recommended timeline for addressing findings?

            4. Risk Mitigation Strategy
            - How should the organization prioritize fixes?
            - What compensating controls can be implemented?
            - What long-term security improvements are recommended?"""

            return self.llm_analyzer.analyze(summary_prompt, summary_stats)

        except Exception as e:
            self.logger.error(f"Error generating executive summary: {str(e)}")
            return self._generate_fallback_summary(findings)

    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
        return severity_counts

    def _generate_fallback_analysis(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback analysis when LLM fails while preserving technical evidence."""
        return {
            'enhanced_analysis': f"Standard analysis for {finding.get('type')} vulnerability. "
                       f"Severity: {finding.get('severity')}. "
                       f"Implement security best practices and conduct thorough testing.",
            'technical_evidence': finding.get('evidence', {}),  # Preserve original evidence
            'generated_at': datetime.utcnow().isoformat(),
            'model_used': 'fallback'
        }

    def _generate_fallback_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Generate fallback executive summary when LLM fails."""
        severity_counts = self._count_severities(findings)
        return f"Security assessment identified {len(findings)} findings. "
               f"Severity distribution: {severity_counts}. "
               f"Implement recommended security controls and conduct regular testing."