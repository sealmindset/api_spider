#!/usr/bin/env python3

import argparse
import json
from ollama import chat

class APILogAnalyzer:
    def __init__(self, model_name='llama3.3'):
        self.model_name = model_name
        self.messages = []
        self.vulnerability_types = [
            'SQLi', 'BOLA', 'Mass Assignment', 'Data Exposure',
            'User/Pass Enumeration', 'Regex DoS', 'Rate Limit',
            'JWT Bypass', 'Unauthorized Password Change'
        ]

    def analyze_log(self, input_log):
        """Analyze security findings from input log file by vulnerability type."""
        try:
            with open(input_log, 'r') as f:
                findings = json.loads(f.read())

            # Group findings by vulnerability type
            findings_by_type = {}
            for finding in findings:
                vuln_type = finding.get('type')
                if vuln_type not in findings_by_type:
                    findings_by_type[vuln_type] = []
                findings_by_type[vuln_type].append(finding)
            
            analysis_results = {}
            
            # Analyze each vulnerability type separately
            for vuln_type, type_findings in findings_by_type.items():
                # Clear previous conversation
                self.messages = []
                
                # Construct detailed prompt for this vulnerability type
                prompt = f"""Please analyze these {vuln_type} findings and determine if they are valid or false positives.
                For each finding, examine:
                1. The complete evidence provided
                2. The attack pattern and payload used
                3. The application's response
                4. Any relationships with other findings
                5. The potential impact and exploitability
                
                Provide a detailed assessment for each finding with:
                - Validation status (Valid/False Positive)
                - Supporting evidence from the finding
                - Reasoning for the determination
                - Recommendations for verification
                
                Findings to analyze:\n{json.dumps(type_findings, indent=2)}"""
                
                self.messages.append({
                    'role': 'user',
                    'content': prompt
                })
                
                # Get analysis from the model
                response = chat(
                    self.model_name,
                    messages=self.messages
                )
                
                # Store analysis results
                analysis_results[vuln_type] = response.message.content
            
            return json.dumps(analysis_results, indent=2)

        except Exception as e:
            return f"Error analyzing log: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='Analyze API security findings using LLM')
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