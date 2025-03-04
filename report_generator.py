#!/usr/bin/env python3

import json
import os
from datetime import datetime
import plotly.graph_objects as go
import plotly.io as pio
from jinja2 import Template

class ReportGenerator:
    def __init__(self):
        import logging
        self.logger = logging.getLogger('report_generator')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
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
            # Skip API workflow test entries and INFO severity findings
            if finding.get('type') == 'API_WORKFLOW_TEST' or finding.get('severity') == 'INFO':
                self.logger.info(f"Skipping finding of type {finding.get('type')} with severity {finding.get('severity')}")
                continue
                
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
            
            # Generate technical details directly from raw findings without LLM
            technical_details = self.generate_technical_details(vuln_type, finding_data, type_findings)
            
            # Initialize LLM analyzer for analysis and developer insights only
            try:
                from llm_analyzer import LLMAnalyzer
                llm = LLMAnalyzer()
                
                # Generate enhanced analysis content using LLM
                analysis_prompt = f"Analyze this {vuln_type} security finding and provide a detailed technical analysis including impact and exploitation scenarios."
                analysis_content = llm.analyze(analysis_prompt, context=finding_data)
                
                # Generate developer insights using LLM
                developer_prompt = f"Analyze this {vuln_type} vulnerability from a developer's perspective. Include root cause analysis and secure coding recommendations."
                developer_insights = llm.analyze(developer_prompt, context=finding_data)
                
                self.logger.info(f"Successfully generated LLM analysis for {vuln_type}")
                
            except Exception as e:
                self.logger.error(f"Error using LLM analyzer: {str(e)}. Falling back to template-based analysis.")
                # Fallback to template-based analysis
                analysis_content = self.generate_enhanced_analysis(vuln_type, finding_data)
                developer_insights = self.generate_developer_insights(vuln_type, finding_data)
            
            # Generate customized remediation steps using LLM
            try:
                from llm_analyzer import chat
                remediation_prompt = f"""Based on the following vulnerability details, provide specific, actionable remediation steps:

Vulnerability Type: {vuln_type}
Severity: {severity}
Description: {finding_data.get('detail', '')}
Attack Pattern: {finding_data.get('attack_pattern', '')}

Provide remediation steps that are:
1. Specific to this vulnerability instance
2. Prioritized by importance
3. Include both immediate fixes and long-term solutions
4. Consider implementation complexity"""
                
                remediation_response = chat('llama3.3', messages=[{"role": "user", "content": remediation_prompt}])
                remediation_steps = remediation_response.message.content.split('\n')
            except Exception:
                # Fallback to template remediation steps
                remediation_steps = self.remediation_templates.get(vuln_type, [])

            # Process the finding data
            processed_findings[vuln_type] = {
                'severity': severity,
                'severity_color': self.severity_colors[severity],
                'analysis': str(analysis_content),
                'technical_details': str(technical_details),
                'remediation_steps': remediation_steps,
                'developer_insights': str(developer_insights)
            }

        # Generate executive summary using LLM
        try:
            from llm_analyzer import chat
            summary_prompt = f"""Generate an executive summary for an API security assessment with the following findings:

Total Findings: {total_findings}
Critical Findings: {critical_findings}
Vulnerability Types: {', '.join(findings_by_type.keys())}

Provide a concise summary that includes:
1. Overall security posture assessment
2. Key risk areas and their business impact
3. Prioritized recommendations
4. Trends and patterns in the findings"""
            
            summary_response = chat('llama3.3', messages=[{"role": "user", "content": summary_prompt}])
            executive_summary = summary_response.message.content
        except Exception:
            # Fallback to basic summary
            executive_summary = f"Found {total_findings} security issues, including {critical_findings} critical vulnerabilities across {len(findings_by_type)} different vulnerability types."

        return processed_findings, total_findings, critical_findings, executive_summary

    def generate_enhanced_analysis(self, vuln_type: str, finding_data: dict) -> str:
        """Generate comprehensive analysis content for the Analysis tab using LLM."""
        # Extract key information for LLM analysis - moved outside try block to ensure availability in except block
        description = finding_data.get('detail', '')
        if not description and 'analysis' in finding_data:
            description = finding_data['analysis']
        
        evidence = finding_data.get('evidence', {})
        attack_pattern = finding_data.get('attack_pattern', '')
        endpoint = finding_data.get('endpoint', 'Not specified')
        parameter = finding_data.get('parameter', 'Not specified')
        severity = finding_data.get('severity', 'MEDIUM')
        impact = finding_data.get('impact', '')
        
        try:
            from llm_analyzer import chat
            
            # Construct prompt for LLM
            prompt = f"""Analyze this {vuln_type} security finding with the following details:

Vulnerability Information:
- Type: {vuln_type}
- Severity: {severity}
- Endpoint: {endpoint}
- Parameter: {parameter}
- Attack Pattern: {attack_pattern}

Technical Details:
{description}

Evidence:
{json.dumps(evidence, indent=2)}

Provide a comprehensive security analysis including:
1. Detailed vulnerability description
2. Attack scenario and potential impact
3. Business risk assessment
4. Real-world exploitation examples
5. Detection and prevention strategies

Format the response in clear sections with markdown headings."""

            # Get enhanced analysis from LLM
            try:
                response = chat('llama3.3', messages=[{"role": "user", "content": prompt}])
                analysis = response.message.content
            except Exception as e:
                # Fallback to template-based analysis if LLM fails
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
- Endpoint: {endpoint}
- Parameter: {parameter}"""
                
            return analysis
            
        except ImportError:
            # Fallback if LLM module is not available
            return f"""Vulnerability Type: {vuln_type}

Description:
{description}

Why This is Dangerous:
- This vulnerability could allow attackers to {self.get_attack_impact(vuln_type)}
- The identified attack pattern ({attack_pattern}) demonstrates active exploitation potential

Impact Analysis:
{impact}

Technical Evidence:
- Attack Pattern: {attack_pattern}
- Endpoint: {endpoint}
- Parameter: {parameter}"""

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
        """Generate technical details focusing on raw evidence and reproduction steps."""
        # Sort findings by severity
        sorted_findings = sorted(raw_findings, key=lambda x: x.get('severity', 'LOW'), reverse=True)
        
        details = []
        for idx, finding in enumerate(sorted_findings, 1):
            # Extract evidence data
            evidence = finding.get('evidence', {})
            if not isinstance(evidence, dict):
                evidence = {}
            
            # Extract request/response information
            request_info = evidence.get('request', {})
            response_info = evidence.get('response', {})
            
            # Build the details section
            details.append(f"Finding #{idx}")
            details.append(f"Severity: {finding.get('severity', 'Unknown')}\n")
            
            # Add endpoint and method information
            endpoint = finding.get('endpoint', evidence.get('url', 'Not specified'))
            method = finding.get('method', request_info.get('method', 'Not specified'))
            details.append(f"Endpoint: {endpoint}")
            details.append(f"Method: {method}\n")
            
            # Add request details
            if request_info:
                details.append("Request Details:")
                if 'headers' in request_info:
                    details.append("Headers:")
                    details.append(json.dumps(request_info['headers'], indent=2))
                if 'body' in request_info:
                    details.append("\nBody:")
                    details.append(json.dumps(request_info['body'], indent=2))
                details.append("")
            
            # Add response details
            if response_info:
                details.append("Response Details:")
                if 'status' in response_info:
                    details.append(f"Status: {response_info['status']}")
                if 'headers' in response_info:
                    details.append("\nHeaders:")
                    details.append(json.dumps(response_info['headers'], indent=2))
                if 'body' in response_info:
                    details.append("\nBody:")
                    details.append(json.dumps(response_info['body'], indent=2))
                details.append("")
            
            # Add attack pattern if available
            attack_pattern = finding.get('attack_pattern')
            if attack_pattern:
                details.append(f"Attack Pattern: {attack_pattern}\n")
            
            # Add raw evidence for complete transparency
            details.append("Raw Evidence:")
            details.append(json.dumps(evidence, indent=2))
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
        """Generate developer-focused insights for a vulnerability."""
        # Extract key information
        description = finding_data.get('detail', '')
        if not description and 'analysis' in finding_data:
            description = finding_data['analysis']
            
        endpoint = finding_data.get('endpoint', 'Not specified')
        parameter = finding_data.get('parameter', 'Not specified')
        attack_pattern = finding_data.get('attack_pattern', '')
        
        # Generate developer insights based on vulnerability type
        insights = f"# Developer Insights: {vuln_type}\n\n"
        
        # Root cause analysis section
        insights += "## Root Cause Analysis\n\n"
        if vuln_type == 'SQLi':
            insights += "- Likely caused by direct concatenation of user input in SQL queries\n"
            insights += "- Missing input validation and parameterized queries\n"
            insights += "- Database access with excessive privileges\n\n"
        elif vuln_type == 'BOLA' or vuln_type == 'IDOR':
            insights += "- Missing object-level authorization checks\n"
            insights += "- Reliance on client-side authorization\n"
            insights += "- Predictable resource identifiers\n\n"
        elif vuln_type == 'Mass Assignment':
            insights += "- Missing property filtering on input objects\n"
            insights += "- Auto-binding of request parameters to model objects\n"
            insights += "- Lack of explicit allowlists for modifiable properties\n\n"
        elif vuln_type == 'JWT Bypass':
            insights += "- Weak signature validation\n"
            insights += "- Missing expiration checks\n"
            insights += "- Improper handling of algorithm selection\n\n"
        elif vuln_type == 'Data Exposure':
            insights += "- Verbose error messages revealing implementation details\n"
            insights += "- Missing data classification and handling policies\n"
            insights += "- Debug endpoints accessible in production\n\n"
        else:
            insights += "- Implementation not following security best practices\n"
            insights += "- Missing proper validation and security controls\n"
            insights += "- Insufficient testing for security edge cases\n\n"
        
        # Code patterns section
        insights += "## Vulnerable Code Patterns\n\n"
        if vuln_type == 'SQLi':
            insights += "```\n// Vulnerable pattern\nquery = \"SELECT * FROM users WHERE username = '\" + username + \"'\";"
            insights += "\n\n// Secure pattern\nquery = \"SELECT * FROM users WHERE username = ?\";"
            insights += "\npreparedStatement.setString(1, username);\n```\n\n"
        elif vuln_type == 'BOLA' or vuln_type == 'IDOR':
            insights += "```\n// Vulnerable pattern"
            insights += "\napp.get('/api/resources/:id', (req, res) => {"
            insights += "\n  const resource = db.getResource(req.params.id);"
            insights += "\n  res.json(resource);"
            insights += "\n});\n"
            insights += "\n// Secure pattern"
            insights += "\napp.get('/api/resources/:id', (req, res) => {"
            insights += "\n  const resource = db.getResource(req.params.id);"
            insights += "\n  if (resource.ownerId !== req.user.id) {"
            insights += "\n    return res.status(403).json({ error: 'Access denied' });"
            insights += "\n  }"
            insights += "\n  res.json(resource);"
            insights += "\n});\n```\n\n"
        elif vuln_type == 'JWT Bypass':
            insights += "```\n// Vulnerable pattern"
            insights += "\nconst payload = jwt.decode(token);"
            insights += "\nif (payload.userId === expectedUserId) {"
            insights += "\n  // Grant access"
            insights += "\n}\n"
            insights += "\n// Secure pattern"
            insights += "\ntry {"
            insights += "\n  const payload = jwt.verify(token, secretKey, {"
            insights += "\n    algorithms: ['RS256'],"
            insights += "\n    issuer: 'trusted-issuer'"
            insights += "\n  });"
            insights += "\n  if (payload.userId === expectedUserId) {"
            insights += "\n    // Grant access"
            insights += "\n  }"
            insights += "\n} catch (err) {"
            insights += "\n  // Invalid token, deny access"
            insights += "\n}\n```\n\n"
        
        # Secure implementation section
        insights += "## Secure Implementation Recommendations\n\n"
        if vuln_type == 'SQLi':
            insights += "1. Use parameterized queries or prepared statements\n"
            insights += "2. Implement input validation with strict type checking\n"
            insights += "3. Apply the principle of least privilege for database access\n"
            insights += "4. Consider using an ORM with built-in SQL injection protection\n"
        elif vuln_type == 'BOLA' or vuln_type == 'IDOR':
            insights += "1. Implement consistent authorization checks at the object level\n"
            insights += "2. Use random, unpredictable resource identifiers\n"
            insights += "3. Maintain access control lists for resources\n"
            insights += "4. Implement proper session management and validation\n"
        elif vuln_type == 'Mass Assignment':
            insights += "1. Explicitly define allowlists for modifiable properties\n"
            insights += "2. Use DTOs (Data Transfer Objects) to control data binding\n"
            insights += "3. Implement property-level access controls\n"
            insights += "4. Validate input against a schema before processing\n"
        elif vuln_type == 'JWT Bypass':
            insights += "1. Use strong algorithms (RS256) with proper key management\n"
            insights += "2. Validate all claims (exp, iss, aud, etc.)\n"
            insights += "3. Implement proper key rotation procedures\n"
            insights += "4. Consider using a token blacklist for revocation\n"
        elif vuln_type == 'Data Exposure':
            insights += "1. Implement proper error handling that doesn't leak implementation details\n"
            insights += "2. Apply the principle of least privilege\n"
            insights += "3. Use environment-specific configurations\n"
            insights += "4. Conduct regular security reviews and testing\n"
        else:
            insights += "1. Follow language and framework-specific security best practices\n"
            insights += "2. Implement comprehensive input validation\n"
            insights += "3. Apply defense in depth with multiple security controls\n"
            insights += "4. Conduct regular security testing and code reviews\n"
        
        # Add specific details about the current finding
        insights += f"\n## Finding-Specific Details\n\n"
        insights += f"- Endpoint: {endpoint}\n"
        insights += f"- Parameter: {parameter}\n"
        if attack_pattern:
            insights += f"- Attack Pattern: {attack_pattern}\n"
        
        return insights

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

            processed_findings, total_findings, critical_findings, executive_summary = self.process_findings(findings)
            
            # Generate charts
            severity_chart = self.generate_severity_chart(processed_findings)

            # Prepare template data
            template_data = {
                'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'executive_summary': executive_summary,
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