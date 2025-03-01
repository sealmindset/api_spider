#!/usr/bin/env python3

import argparse
import json
import time
from typing import Dict, List, Optional
from ollama import chat

class APILogAnalyzer:
    def __init__(self, model_name='llama3.3'):
        self.model_name = model_name
        self.messages = []
        self.context_store = {}
        self.relationship_graph = {}
        self.vulnerability_types = [
            'SQLi', 'BOLA', 'Mass Assignment', 'Data Exposure',
            'User/Pass Enumeration', 'Regex DoS', 'Rate Limit',
            'JWT Bypass', 'Unauthorized Password Change'
        ]
        self.remediation_templates = {
            'SQLi': ['Use parameterized queries', 'Input validation', 'Least privilege access'],
            'BOLA': ['Implement proper access controls', 'Object-level authorization checks'],
            'Mass Assignment': ['Whitelist allowed fields', 'Implement strict schema validation'],
            'Data Exposure': ['Implement proper data classification', 'Encryption at rest and transit'],
            'JWT Bypass': ['Implement proper JWT validation', 'Use secure signing algorithms'],
            'Rate Limit': ['Implement rate limiting per user/IP', 'Use token bucket algorithm'],
            'Regex DoS': ['Review regex patterns', 'Implement timeout mechanisms']
        }

    def build_context(self, finding: Dict) -> str:
        """Build context for a finding using historical data and relationships."""
        context = []
        
        # Add historical context for this vulnerability type
        vuln_type = finding.get('type')
        if vuln_type in self.context_store:
            context.append(f"Previous findings of type {vuln_type}: {self.context_store[vuln_type]}")
        
        # Add relationship context
        finding_id = finding.get('id')
        if finding_id in self.relationship_graph:
            related = self.relationship_graph[finding_id]
            context.append(f"Related findings: {related}")
        
        # Add remediation template context
        if vuln_type in self.remediation_templates:
            context.append(f"Common remediation steps: {', '.join(self.remediation_templates[vuln_type])}")
        
        return '\n'.join(context)

    def update_relationships(self, findings: List[Dict]):
        """Update the relationship graph based on findings analysis."""
        for finding in findings:
            finding_id = finding.get('id')
            if not finding_id:
                continue
                
            # Look for related findings based on endpoints, parameters, or attack patterns
            related = []
            for other in findings:
                if other.get('id') != finding_id:
                    if (finding.get('endpoint') == other.get('endpoint') or
                        finding.get('parameter') == other.get('parameter') or
                        finding.get('attack_pattern') == other.get('attack_pattern')):
                        related.append(other.get('id'))
            
            if related:
                self.relationship_graph[finding_id] = related

    def analyze_log(self, input_log: str) -> str:
        """Analyze security findings from input log file with enhanced context and relationships."""
        try:
            with open(input_log, 'r') as f:
                findings = json.loads(f.read())

            # Update relationships between findings
            self.update_relationships(findings)

            # Group findings by vulnerability type
            findings_by_type = {}
            for finding in findings:
                vuln_type = finding.get('type')
                if vuln_type not in findings_by_type:
                    findings_by_type[vuln_type] = []
                findings_by_type[vuln_type].append(finding)
            
            analysis_results = {}
            
            # Analyze each vulnerability type with enhanced context
            for vuln_type, type_findings in findings_by_type.items():
                # Maintain conversation history for better context
                if vuln_type not in self.context_store:
                    self.context_store[vuln_type] = []
                
                # Build comprehensive analysis prompt
                prompt = f"""Analyze these {vuln_type} findings with the following context and requirements:

                Context:
                {self.build_context(type_findings[0])}

                For each finding, provide:
                1. Validation Status:
                   - Confidence score (0-1)
                   - Supporting evidence
                   - False positive indicators if any

                2. Technical Analysis:
                   - Attack pattern evaluation
                   - Payload analysis
                   - Response behavior analysis
                   - Security control bypass methods

                3. Impact Assessment:
                   - Business impact
                   - Data sensitivity
                   - Exploitation complexity
                   - Attack prerequisites

                4. Remediation Guidance:
                   - Immediate mitigation steps
                   - Long-term fixes
                   - Security control recommendations
                   - Testing validation steps

                5. Related Vulnerabilities:
                   - Attack chain potential
                   - Compound vulnerability scenarios
                   - Security control gaps

                Findings to analyze:
                {json.dumps(type_findings, indent=2)}"""

                self.messages.append({
                    'role': 'user',
                    'content': prompt
                })
                
                # Get enhanced analysis from the model
                response = chat(
                    self.model_name,
                    messages=self.messages
                )
                
                # Update context store with analysis results
                self.context_store[vuln_type].append({
                    'timestamp': int(time.time()),
                    'analysis': response.message.content
                })
                
                # Store analysis results
                analysis_results[vuln_type] = {
                    'analysis': response.message.content,
                    'context': self.build_context(type_findings[0]),
                    'relationships': [self.relationship_graph.get(f['id'], []) for f in type_findings],
                    'remediation_template': self.remediation_templates.get(vuln_type, [])
                }
            
            return json.dumps(analysis_results, indent=2)

        except Exception as e:
            return f"Error analyzing log: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='Analyze API security findings using LLM with enhanced context awareness')
    parser.add_argument('--input', required=True, help='Input log file containing security findings')
    parser.add_argument('--output', required=True, help='Output file for analysis results')
    parser.add_argument('--model', default='llama3.3', help='LLM model name to use')
    
    args = parser.parse_args()
    
    analyzer = APILogAnalyzer(model_name=args.model)
    analysis = analyzer.analyze_log(args.input)
    
    with open(args.output, 'w') as f:
        f.write(analysis)

if __name__ == '__main__':
    main()