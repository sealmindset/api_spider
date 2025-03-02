#!/usr/bin/env python3

import json
import os
from datetime import datetime
import plotly.graph_objects as go
import plotly.io as pio
from jinja2 import Template

class ReportGenerator:
    def __init__(self):
        self.severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        
        self.remediation_templates = {
            'SQLi': ['Use parameterized queries', 'Input validation', 'Least privilege access'],
            'BOLA': ['Implement proper access controls', 'Object-level authorization checks'],
            'Mass Assignment': ['Whitelist allowed fields', 'Implement strict schema validation'],
            'Data Exposure': ['Implement proper data classification', 'Encryption at rest and transit'],
            'JWT Bypass': ['Implement proper JWT validation', 'Use secure signing algorithms'],
            'Rate Limit': ['Implement rate limiting per user/IP', 'Use token bucket algorithm'],
            'Regex DoS': ['Review regex patterns', 'Implement timeout mechanisms'],
            'User/Pass Enumeration': ['Implement consistent error messages', 'Add rate limiting to authentication endpoints'],
            'Unauthorized Password Change': ['Enforce re-authentication for sensitive operations', 'Implement proper session validation'],
            'CREDENTIAL_EXPOSURE': ['Remove debug endpoints in production', 'Implement proper access controls', 'Encrypt sensitive data']
        }
        
        self.html_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Security Analysis Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; }
                .severity-badge {
                    padding: 5px 10px;
                    border-radius: 4px;
                    color: white;
                    font-weight: bold;
                }
                .finding-card {
                    margin-bottom: 20px;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .chart-container {
                    height: 400px;
                    margin: 20px 0;
                }
                .technical-details {
                    font-family: monospace;
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                }
                .nav-tabs .nav-link {
                    color: #495057;
                }
                .nav-tabs .nav-link.active {
                    font-weight: bold;
                }
                .tab-content {
                    padding: 20px;
                    border: 1px solid #dee2e6;
                    border-top: none;
                    border-radius: 0 0 5px 5px;
                }
            </style>
        </head>
        <body>
            <div class="container my-5">
                <h1 class="mb-4">API Security Analysis Report</h1>
                <p class="text-muted">Generated on: {{ generation_date }}</p>
                
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Executive Summary</h5>
                                <p>{{ executive_summary }}</p>
                                <div class="chart-container" id="severityChart"></div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Key Statistics</h5>
                                <ul class="list-unstyled">
                                    {% for stat in key_stats %}
                                    <li class="mb-2">{{ stat }}</li>
                                    {% endfor %}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <h2 class="mb-4">Vulnerability Findings</h2>
                {% for vuln_type, data in findings.items() %}
                <div class="finding-card p-4 mb-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h3>{{ vuln_type }}</h3>
                        <div class="severity-badge" style="background-color: {{ data.severity_color }}">{{ data.severity }}</div>
                    </div>
                    
                    <ul class="nav nav-tabs" id="myTab{{ loop.index }}" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="analysis-tab{{ loop.index }}" data-bs-toggle="tab" data-bs-target="#analysis{{ loop.index }}" type="button" role="tab">Analysis</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="technical-tab{{ loop.index }}" data-bs-toggle="tab" data-bs-target="#technical{{ loop.index }}" type="button" role="tab">Technical Details</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="remediation-tab{{ loop.index }}" data-bs-toggle="tab" data-bs-target="#remediation{{ loop.index }}" type="button" role="tab">Remediation</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="developer-tab{{ loop.index }}" data-bs-toggle="tab" data-bs-target="#developer{{ loop.index }}" type="button" role="tab">Developer Insights</button>
                        </li>
                    </ul>
                    
                    <div class="tab-content" id="myTabContent{{ loop.index }}">
                        <div class="tab-pane fade show active" id="analysis{{ loop.index }}" role="tabpanel">
                            <p>{{ data.analysis }}</p>
                        </div>
                        
                        <div class="tab-pane fade" id="technical{{ loop.index }}" role="tabpanel">
                            <div class="technical-details">
                                <pre>{{ data.technical_details }}</pre>
                            </div>
                        </div>
                        
                        <div class="tab-pane fade" id="remediation{{ loop.index }}" role="tabpanel">
                            <ul>
                                {% for step in data.remediation_steps %}
                                <li>{{ step }}</li>
                                {% endfor %}
                            </ul>
                        </div>
                        
                        <div class="tab-pane fade" id="developer{{ loop.index }}" role="tabpanel">
                            <div class="technical-details">
                                <pre>{{ data.developer_insights }}</pre>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>

            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
            {{ charts_js }}
        </body>
        </html>
        '''

    def generate_severity_chart(self, findings):
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings.values():
            severity = finding.get('severity', 'MEDIUM')
            severity_counts[severity] += 1

        fig = go.Figure(data=[go.Bar(
            x=list(severity_counts.keys()),
            y=list(severity_counts.values()),
            marker_color=[self.severity_colors[sev] for sev in severity_counts.keys()]
        )])

        fig.update_layout(
            title='Vulnerability Severity Distribution',
            xaxis_title='Severity Level',
            yaxis_title='Number of Findings',
            template='plotly_white'
        )

        return pio.to_html(fig, full_html=False)

    def process_findings(self, findings):
        processed_findings = {}
        total_findings = 0
        critical_findings = 0

        # Group findings by vulnerability type
        findings_by_type = {}
        for finding in findings:
            # Normalize vulnerability type names
            vuln_type = finding.get('type')
            if vuln_type == 'SQL_INJECTION':
                vuln_type = 'SQLi'
            if vuln_type == 'CREDENTIAL_EXPOSURE':
                vuln_type = 'Data Exposure'

            if vuln_type not in findings_by_type:
                findings_by_type[vuln_type] = []
            findings_by_type[vuln_type].append(finding)

        # Process each vulnerability type
        for vuln_type, type_findings in findings_by_type.items():
            finding_data = type_findings[0] if type_findings else {}
            
            # Extract severity from the findings
            severity = 'MEDIUM'  # Default severity
            for finding in type_findings:
                if finding.get('severity') == 'CRITICAL':
                    severity = 'CRITICAL'
                    critical_findings += 1
                    break
                elif finding.get('severity') == 'HIGH' and severity != 'CRITICAL':
                    severity = 'HIGH'
            total_findings += len(type_findings)
            
            # Generate enhanced analysis content
            analysis_content = self.generate_enhanced_analysis(vuln_type, finding_data)
            
            # Generate technical details focusing on highest severity findings
            technical_details = self.generate_technical_details(vuln_type, finding_data, type_findings)
            
            # Generate developer insights focusing on root cause
            developer_insights = self.generate_developer_insights(vuln_type, finding_data)

            # Process the finding data
            processed_findings[vuln_type] = {
                'severity': severity,
                'severity_color': self.severity_colors[severity],
                'analysis': str(analysis_content),
                'technical_details': str(technical_details),
                'remediation_steps': [str(step) for step in self.remediation_templates.get(vuln_type, [])],
                'developer_insights': str(developer_insights)
            }

        return processed_findings, total_findings, critical_findings

    def generate_enhanced_analysis(self, vuln_type: str, finding_data: dict) -> str:
        """Generate comprehensive analysis content for the Analysis tab."""
        # Handle case where finding_data contains an 'analysis' field with complete analysis
        if 'analysis' in finding_data and isinstance(finding_data['analysis'], str) and len(finding_data['analysis']) > 100:
            # If we have a complete analysis, use it directly
            return finding_data['analysis']
            
        # Otherwise, build analysis from individual fields
        description = finding_data.get('detail', '')
        if not description and 'analysis' in finding_data:
            description = finding_data['analysis']

        # Build impact analysis
        impact = finding_data.get('impact', 'Potential security impact not specified')
        
        # Get evidence details
        evidence = finding_data.get('evidence', {})
        attack_pattern = finding_data.get('attack_pattern', '')
        
        analysis = f"""Vulnerability Type: {vuln_type}

Description:
{description}

Why This is Dangerous:
- This vulnerability could allow attackers to {self.get_attack_impact(vuln_type)}
- The identified attack pattern ({attack_pattern}) demonstrates active exploitation potential

Impact Analysis:
{impact}

Technical Evidence:
- Attack Pattern: {attack_pattern}
- Endpoint: {finding_data.get('endpoint', 'Not specified')}
- Parameter: {finding_data.get('parameter', 'Not specified')}"""

        return analysis

    def get_attack_impact(self, vuln_type: str) -> str:
        """Get description of potential attack impact for a vulnerability type."""
        impact_map = {
            'SQLi': 'execute arbitrary SQL commands and potentially access, modify or delete sensitive data',
            'BOLA': 'access unauthorized resources and data belonging to other users',
            'Mass Assignment': 'modify protected attributes and potentially escalate privileges',
            'Data Exposure': 'access sensitive information that should be protected',
            'JWT Bypass': 'forge authentication tokens and impersonate other users',
            'Rate Limit': 'perform brute force attacks or cause denial of service',
            'Regex DoS': 'cause denial of service through resource exhaustion',
            'User/Pass Enumeration': 'enumerate valid usernames and perform targeted attacks',
            'Unauthorized Password Change': 'take over user accounts by changing their passwords'
        }
        return impact_map.get(vuln_type, 'exploit the system in unexpected ways')

    def generate_technical_details(self, vuln_type: str, finding_data: dict, raw_findings: list) -> str:
        """Generate technical details focusing on highest severity findings with enhanced analysis."""
        # Sort findings by severity
        sorted_findings = sorted(raw_findings, key=lambda x: x.get('severity', 'LOW'), reverse=True)
        
        # Take top 5 highest severity findings
        top_findings = sorted_findings[:5] if sorted_findings else [finding_data]
        
        details = []
        for idx, finding in enumerate(top_findings, 1):
            # Extract evidence data, handling both direct and nested formats
            evidence = finding.get('evidence', {})
            if not isinstance(evidence, dict):
                evidence = {}
                
            # Extract method from finding or evidence
            method = finding.get('method')
            if not method and isinstance(evidence, dict):
                if 'jwt_request' in evidence and isinstance(evidence['jwt_request'], dict):
                    method = evidence['jwt_request'].get('method')
                elif 'request' in evidence and isinstance(evidence['request'], dict):
                    method = evidence['request'].get('method')
                elif 'payload' in evidence:
                    payload = str(evidence['payload'])
                    if ' ' in payload and payload.split(' ')[0] in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        method = payload.split(' ')[0]
            
            # Format finding details with proper fallbacks
            severity = str(finding.get('severity', 'Unknown'))
            # Extract endpoint from finding or evidence
            endpoint = finding.get('endpoint')
            if not endpoint and isinstance(evidence, dict):
                if 'jwt_request' in evidence and isinstance(evidence['jwt_request'], dict):
                    endpoint = evidence['jwt_request'].get('url')
                elif 'url' in evidence:
                    endpoint = evidence['url']
            endpoint = str(endpoint if endpoint else 'Not specified')
            attack_pattern = str(finding.get('attack_pattern', ''))
            detail = str(finding.get('detail', ''))
            
            # Build the details section
            details.append(f"Finding #{idx} (Severity: {severity})\n")
            if detail:
                details.append(f"Description: {detail}\n")
            details.append(f"Endpoint: {endpoint}")
            details.append(f"Method: {method if method else 'Not specified'}")
            if attack_pattern:
                details.append(f"Attack Pattern: {attack_pattern}\n")
            else:
                details.append("Attack Pattern: Not specified\n")
            
            # Add evidence details with proper formatting for all vulnerability types
            if vuln_type in ['JWT_WEAK_KEY', 'JWT_ALG_NONE', 'JWT Bypass']:
                details.append("\nJWT Analysis:")
                if 'jwt_request' in evidence:
                    details.append("Request Details:")
                    jwt_req = evidence['jwt_request']
                    details.append(f"- Method: {jwt_req.get('method', 'Not specified')}")
                    details.append(f"- URL: {jwt_req.get('url', 'Not specified')}")
                    details.append(f"- Authorization: {jwt_req.get('headers', {}).get('Authorization', 'Not specified')}")
                    
                    if 'auth_state' in jwt_req:
                        details.append("\nAuthentication State:")
                        auth_state = jwt_req['auth_state']
                        details.append(f"- Auth Type: {auth_state.get('auth_type', 'Not specified')}")
                        if 'weak_key' in auth_state:
                            details.append(f"- Weak Key: {auth_state['weak_key']}")
                        if 'attack' in auth_state:
                            details.append(f"- Attack Type: {auth_state['attack']}")
                
                if 'jwt_response' in evidence:
                    details.append("\nResponse Details:")
                    jwt_resp = evidence['jwt_response']
                    details.append(f"- Status Code: {jwt_resp.get('status_code', 'Not specified')}")
                    details.append(f"- Body: {jwt_resp.get('body', 'Not specified')}")
                
                if 'payload' in evidence:
                    details.append("\nPayload Details:")
                    payload = evidence['payload']
                    details.append(f"- Content: {json.dumps(payload, indent=2)}")
                details.append("")
            
            elif vuln_type == 'SQLi':
                details.append("\nSQL Injection Analysis:")
                details.append("- Query Structure: " + str(self.analyze_sql_pattern(str(evidence.get('code', '')))))
                details.append("- Injection Point: " + str(self.identify_injection_point(str(evidence.get('payload', '')))))
                if 'request' in evidence:
                    details.append("\nRequest Details:")
                    req = evidence['request']
                    details.append(f"- Method: {req.get('method', 'Not specified')}")
                    details.append(f"- URL: {req.get('url', 'Not specified')}")
                    details.append(f"- Parameters: {req.get('params', 'Not specified')}")
                if 'response' in evidence:
                    details.append("\nResponse Details:")
                    resp = evidence['response']
                    details.append(f"- Status Code: {resp.get('status_code', 'Not specified')}")
                    details.append(f"- Body: {resp.get('body', 'Not specified')}")
                details.append("")
            
            elif vuln_type == 'BOLA':
                details.append("\nAccess Control Analysis:")
                details.append("- Authorization Check: " + str(self.analyze_auth_check(str(evidence.get('code', '')))))
                details.append("- Access Pattern: " + str(self.analyze_access_pattern(str(evidence.get('payload', '')))))
                if 'request' in evidence:
                    details.append("\nRequest Details:")
                    req = evidence['request']
                    details.append(f"- Method: {req.get('method', 'Not specified')}")
                    details.append(f"- URL: {req.get('url', 'Not specified')}")
                    details.append(f"- Headers: {req.get('headers', 'Not specified')}")
                if 'response' in evidence:
                    details.append("\nResponse Details:")
                    resp = evidence['response']
                    details.append(f"- Status Code: {resp.get('status_code', 'Not specified')}")
                    details.append(f"- Body: {resp.get('body', 'Not specified')}")
                details.append("")
            
            elif vuln_type == 'Mass Assignment':
                details.append("\nMass Assignment Analysis:")
                details.append("- Vulnerability: Unfiltered parameter binding")
                details.append("- Impact: Privilege escalation or data manipulation")
                if 'request' in evidence:
                    details.append("\nRequest Details:")
                    req = evidence['request']
                    details.append(f"- Method: {req.get('method', 'Not specified')}")
                    details.append(f"- URL: {req.get('url', 'Not specified')}")
                    details.append(f"- Body: {req.get('body', 'Not specified')}")
                if 'response' in evidence:
                    details.append("\nResponse Details:")
                    resp = evidence['response']
                    details.append(f"- Status Code: {resp.get('status_code', 'Not specified')}")
                    details.append(f"- Body: {resp.get('body', 'Not specified')}")
                details.append("")
            
            elif vuln_type == 'Data Exposure' or finding.get('type') == 'EXCESSIVE_DATA_EXPOSURE':
                details.append(f"URL: {evidence.get('url', 'Not specified')}")
                details.append("Request Headers: Not available")
                details.append("Request Body: Not available")
                
                if 'exposed_data_types' in evidence:
                    details.append("Exposed Data Types:")
                    for data_type in evidence['exposed_data_types']:
                        details.append(f"- {data_type}")
                    details.append("")
                
                details.append("Response Headers: Not available")
                if 'response_sample' in evidence:
                    details.append("Response Body:")
                    details.append(evidence['response_sample'])
                details.append("")
            
            elif vuln_type == 'Rate Limit':
                details.append("\nRate Limit Analysis:")
                details.append("- Vulnerability: Missing or insufficient rate limiting")
                details.append("- Impact: Potential for brute force or DoS attacks")
                if 'request' in evidence:
                    details.append("\nRequest Details:")
                    req = evidence['request']
                    details.append(f"- Method: {req.get('method', 'Not specified')}")
                    details.append(f"- URL: {req.get('url', 'Not specified')}")
                    details.append(f"- Rate: {req.get('rate', 'Not specified')} requests")
                if 'response' in evidence:
                    details.append("\nResponse Details:")
                    resp = evidence['response']
                    details.append(f"- Status Code: {resp.get('status_code', 'Not specified')}")
                    details.append(f"- Headers: {resp.get('headers', 'Not specified')}")
                details.append("")
            
            # Add evidence details with proper formatting
            if evidence:
                if 'code' in evidence:
                    details.append("\nVulnerable Code:")
                    details.append(str(evidence['code']))
                if 'request' in evidence:
                    details.append("\nRequest Details:")
                    details.append(str(evidence['request']))
                if 'response' in evidence:
                    details.append("\nResponse Details:")
                    details.append(str(evidence['response']))
                if 'sample' in evidence:
                    details.append("\nSample Data:")
                    details.append(str(evidence['sample']))
                details.append("\nAnalysis:")
                details.append(str(self.analyze_response(evidence.get('response', evidence.get('sample', '')), vuln_type)))
            details.append("\n" + "-"*50 + "\n")
        
        return "\n".join(str(detail) for detail in details)

    def analyze_sql_pattern(self, code: str) -> str:
        if not code:
            return "No code available for analysis"
        if '${' in code or '+' in code:
            return "Direct string concatenation detected - HIGH RISK"
        if 'LIKE' in code.upper():
            return "LIKE operator usage detected - potential wildcard injection"
        return "Standard query structure"

    def analyze_auth_check(self, code: str) -> str:
        if not code:
            return "No code available for analysis"
        if 'session' in code.lower():
            return "Session-based authorization present"
        if 'auth' in code.lower() or 'verify' in code.lower():
            return "Authorization check present but may be insufficient"
        return "No explicit authorization checks found"

    def analyze_access_pattern(self, payload: str) -> str:
        if not payload:
            return "No payload available for analysis"
        if 'id' in payload.lower():
            return "Direct object reference manipulation attempted"
        return "Standard access pattern"

    def identify_injection_point(self, payload: str) -> str:
        if not payload:
            return "No payload available for analysis"
        if "'" in payload:
            return "String literal boundary"
        if ";" in payload:
            return "Query separator"
        if "--" in payload:
            return "Comment injection"
        return "Unknown injection point"

    def analyze_payload(self, payload: str, vuln_type: str) -> str:
        if not payload:
            return "No payload available for analysis"
        
        if vuln_type == 'SQLi':
            if "UNION" in payload.upper():
                return "UNION-based injection attempt - data extraction"
            if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper():
                return "Time-based blind injection attempt"
            if "OR" in payload.upper() and "=" in payload:
                return "Boolean-based injection attempt"
        elif vuln_type == 'XSS':
            if "<script" in payload.lower():
                return "Basic script injection attempt"
            if "onerror" in payload.lower() or "onload" in payload.lower():
                return "Event handler injection attempt"
        elif vuln_type == 'JWT Bypass':
            if "alg" in payload.lower() and "none" in payload.lower():
                return "Algorithm 'none' attack - signature validation bypass"
            if "eyj" in payload.lower():
                return "Manipulated JWT token structure"
        elif vuln_type == 'BOLA':
            if "/" in payload and any(str(i) in payload for i in range(10)):
                return "Direct object reference manipulation"
        elif vuln_type == 'Mass Assignment':
            if "admin" in payload.lower() or "role" in payload.lower() or "permission" in payload.lower():
                return "Privilege escalation attempt via mass assignment"
        elif vuln_type == 'Rate Limit':
            return "Multiple rapid requests to bypass rate limiting"
        elif vuln_type == 'Regex DoS':
            if any(c * 5 in payload for c in '.*+?{}'): # Repeated regex metacharacters
                return "Regex DoS payload with catastrophic backtracking pattern"
        
        return "Standard payload structure"

    def analyze_response(self, response: str, vuln_type: str) -> str:
        if not response:
            return "No response available for analysis"
        
        try:
            # Handle both string and dictionary responses
            response_data = json.loads(response) if isinstance(response, str) else response
            
            # Convert response_data to string for consistent analysis
            response_str = str(response_data)
                
            if 'error' in response_str:
                return "Error message exposure - potential information leakage"
            if 'stack' in response_str.lower():
                return "Stack trace exposure detected"
            if len(response_str) > 1000:
                return "Large response size - potential data dump"
            
            # Additional analysis based on vulnerability type
            if vuln_type == 'SQLi' and any(keyword in response_str.lower() for keyword in ['sql', 'query', 'syntax']):
                return "SQL error messages exposed in response"
            elif vuln_type == 'JWT Bypass' and any(keyword in response_str.lower() for keyword in ['token', 'jwt', 'auth']):
                return "Authentication/token information exposed"
            elif vuln_type == 'Data Exposure' and any(keyword in response_str.lower() for keyword in ['password', 'secret', 'key', 'private']):
                return "Sensitive data exposed in response"
            
            return "Standard response structure"
        except (json.JSONDecodeError, AttributeError):
            if isinstance(response, str) and 'error' in response.lower():
                return "Error message in non-JSON response"
            return "Non-JSON response structure"

    def generate_developer_insights(self, vuln_type: str, finding_data: dict) -> str:
        """Generate comprehensive developer insights with root cause analysis and best practices."""
        evidence = finding_data.get('evidence', {})
        code_sample = evidence.get('code', 'No code sample available')
        
        insights = [f"Root Cause Analysis for {vuln_type}:\n"]
        
        # Analyze code patterns and architecture
        if code_sample != 'No code sample available':
            insights.append("1. Code Analysis:")
            insights.append("   Vulnerable Code Pattern:")
            insights.append(f"   {str(code_sample)}")
            insights.append("\n   Identified Issues:")
            insights.extend([f"   {str(issue)}" for issue in self.analyze_code_issues(vuln_type, code_sample)])
            
            # Add architectural analysis
            insights.append("\n2. Architectural Analysis:")
            arch_issues = self.analyze_architecture(vuln_type, finding_data)
            insights.extend([f"   {str(issue)}" for issue in arch_issues])
            
            # Add security control analysis
            insights.append("\n3. Missing Security Controls:")
            controls = self.identify_missing_controls(vuln_type, code_sample)
            insights.extend([f"   {str(control)}" for control in controls])
        
        # Add secure coding recommendations with examples
        insights.append("\n4. Secure Implementation Guide:")
        insights.extend([str(example) for example in self.generate_secure_examples(vuln_type)])
        
        # Add testing recommendations
        insights.append("\n5. Security Testing Recommendations:")
        insights.extend([str(rec) for rec in self.generate_testing_guide(vuln_type)])
        
        return "\n".join(insights)

    def analyze_architecture(self, vuln_type: str, finding_data: dict) -> list:
        issues = []
        endpoint = finding_data.get('endpoint', '')
        
        if vuln_type == 'SQLi':
            issues.append("- Missing data access layer abstraction")
            issues.append("- Direct database query execution in controller layer")
        elif vuln_type == 'BOLA':
            issues.append("- Missing centralized authorization layer")
            issues.append("- Insufficient separation between authentication and authorization")
        elif vuln_type == 'JWT Bypass':
            issues.append("- Missing token validation middleware")
            issues.append("- Insufficient JWT configuration management")
        
        if '/api/v1/' in endpoint:
            issues.append("- API versioning indicates potential for legacy security issues")
        
        return issues

    def identify_missing_controls(self, vuln_type: str, code_sample: str) -> list:
        controls = []
        
        if vuln_type == 'SQLi':
            if 'prepare' not in code_sample.lower():
                controls.append("- Missing prepared statements")
            if 'escape' not in code_sample.lower():
                controls.append("- Missing input escaping")
            controls.append("- Missing input validation layer")
        elif vuln_type == 'XSS':
            if 'escape' not in code_sample.lower() and 'sanitize' not in code_sample.lower():
                controls.append("- Missing output encoding")
            controls.append("- Missing Content Security Policy (CSP)")
        elif vuln_type == 'BOLA':
            if 'rbac' not in code_sample.lower() and 'acl' not in code_sample.lower():
                controls.append("- Missing role-based access control")
            controls.append("- Missing object-level permission checks")
        
        return controls

    def generate_secure_examples(self, vuln_type: str) -> list:
        examples = ["Secure Implementation Examples:"]
        
        if vuln_type == 'SQLi':
            examples.extend([
                "   Instead of:",
                "   const query = `SELECT * FROM users WHERE id = ${id}`;\n",
                "   Use:",
                "   const query = 'SELECT * FROM users WHERE id = ?';\n",
                "   const [rows] = await connection.execute(query, [id]);"
            ])
        elif vuln_type == 'BOLA':
            examples.extend([
                "   Instead of:",
                "   app.get('/api/users/:id', (req, res) => {\n",
                "     const userId = req.params.id;\n",
                "     const user = getUserById(userId);\n",
                "     res.json(user);\n",
                "   });\n",
                "   Use:",
                "   app.get('/api/users/:id', authenticate, async (req, res) => {\n",
                "     const userId = req.params.id;\n",
                "     if (!await hasPermission(req.user, 'read', 'user', userId)) {\n",
                "       return res.status(403).json({ error: 'Unauthorized' });\n",
                "     }\n",
                "     const user = await getUserById(userId);\n",
                "     res.json(user);\n",
                "   });"
            ])
        
        return examples

    def generate_testing_guide(self, vuln_type: str) -> list:
        guide = ["Security Testing Checklist:"]
        
        if vuln_type == 'SQLi':
            guide.extend([
                "   - Test with various SQL metacharacters: ', \", ), ;, --, #",
                "   - Attempt UNION-based injections",
                "   - Test for blind SQL injection using time delays",
                "   - Verify error messages are not exposed"
            ])
        elif vuln_type == 'BOLA':
            guide.extend([
                "   - Test access to resources with different user roles",
                "   - Verify direct object reference handling",
                "   - Check for horizontal and vertical privilege escalation",
                "   - Test API endpoints with unauthorized tokens"
            ])
        
        return guide

    def analyze_code_issues(self, vuln_type: str, code_sample: str) -> list:
        """Analyze code sample for specific security issues."""
        issues = []
        
        if vuln_type == 'SQLi' and ('${' in code_sample or '+' in code_sample):
            issues.append("- Direct string concatenation in SQL queries")
            issues.append("- Missing parameter sanitization")
        elif vuln_type == 'BOLA' and 'params.id' in code_sample:
            issues.append("- Missing authorization checks")
            issues.append("- Direct use of user input without validation")
        elif vuln_type == 'Mass Assignment' and 'req.body' in code_sample:
            issues.append("- Unfiltered mass assignment")
            issues.append("- Missing property whitelist")
        elif vuln_type == 'JWT Bypass' and 'verify' in code_sample:
            issues.append("- Insufficient JWT validation")
            issues.append("- Missing algorithm verification")
        
        if not issues:
            issues.append("- Code requires manual review for security issues")
        
        return issues

    def determine_severity(self, finding_data):
        # Implement severity determination logic based on the finding data
        if 'SQLi' in finding_data.get('analysis', '').upper() or 'CRITICAL' in finding_data.get('analysis', '').upper():
            return 'CRITICAL'
        elif 'HIGH' in finding_data.get('analysis', '').upper():
            return 'HIGH'
        elif 'MEDIUM' in finding_data.get('analysis', '').upper():
            return 'MEDIUM'
        else:
            return 'LOW'

    def generate_report(self, input_file: str, output_file: str):
        try:
            with open(input_file, 'r') as f:
                findings = json.loads(f.read())

            processed_findings, total_findings, critical_findings = self.process_findings(findings)
            
            # Generate charts
            severity_chart = self.generate_severity_chart(processed_findings)

            # Prepare template data
            template_data = {
                'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'executive_summary': f"Security analysis identified {total_findings} vulnerabilities, "
                                   f"including {critical_findings} critical findings that require immediate attention.",
                'key_stats': [
                    f"Total Vulnerabilities: {total_findings}",
                    f"Critical Findings: {critical_findings}",
                    f"Unique Vulnerability Types: {len(processed_findings)}"
                ],
                'findings': processed_findings,
                'charts_js': severity_chart
            }

            # Generate HTML report
            template = Template(self.html_template)
            html_report = template.render(**template_data)

            with open(output_file, 'w') as f:
                f.write(html_report)

            print(f"Report generated successfully: {output_file}")

        except Exception as e:
            print(f"Error generating report: {str(e)}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python report_generator.py <input_log_file> <output_html_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)

    generator = ReportGenerator()
    generator.generate_report(input_file, output_file)

if __name__ == '__main__':
    import sys
    main()