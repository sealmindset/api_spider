#!/usr/bin/env python3

import argparse
import json
import time
import re
import os
import statistics
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple, Set, Any
from ollama import chat

class EnhancedAPILogAnalyzer:
    def __init__(self, model_name='llama3.3'):
        self.model_name = model_name
        self.messages = []
        self.context_store = {}
        self.relationship_graph = {}
        self.endpoint_patterns = {}
        self.developer_signatures = {}
        self.coding_patterns = defaultdict(int)
        self.framework_indicators = defaultdict(int)
        self.security_awareness_score = 0
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
            'Regex DoS': ['Review regex patterns', 'Implement timeout mechanisms'],
            'User/Pass Enumeration': ['Implement consistent error messages', 'Add rate limiting to authentication endpoints'],
            'Unauthorized Password Change': ['Enforce re-authentication for sensitive operations', 'Implement proper session validation']
        }
        
        # Framework detection patterns
        self.framework_patterns = {
            'Spring': [r'@Controller', r'@RestController', r'@RequestMapping', r'@Autowired'],
            'Django': [r'django\.', r'@api_view', r'serializers\.', r'models\.Model'],
            'Flask': [r'@app\.route', r'flask\.', r'request\.json', r'jsonify'],
            'Express': [r'app\.use\(', r'app\.get\(', r'app\.post\(', r'express\.Router\('],
            'Laravel': [r'Route::', r'->middleware', r'Eloquent', r'Controller@'],
            'ASP.NET': [r'\[HttpGet\]', r'\[ApiController\]', r'IActionResult', r'Controller']
        }
        
        # Developer signature patterns
        self.signature_patterns = {
            'naming_conventions': {
                'camelCase': r'[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*',
                'snake_case': r'[a-z][a-z0-9]*(_[a-z0-9]+)+',
                'PascalCase': r'[A-Z][a-zA-Z0-9]*',
                'kebab-case': r'[a-z][a-z0-9]*(-[a-z0-9]+)+'
            },
            'comment_styles': {
                'javadoc': r'/\*\*.*?\*/',
                'block': r'/\*.*?\*/',
                'line': r'//.*?$',
                'hash': r'#.*?$'
            },
            'indentation': {
                'spaces_2': r'^  [^\s]',
                'spaces_4': r'^    [^\s]',
                'tabs': r'^\t[^\s]'
            }
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
    
    def extract_endpoint_patterns(self, findings: List[Dict]):
        """Extract patterns from API endpoints to identify API design practices."""
        endpoints = []
        for finding in findings:
            endpoint = finding.get('endpoint') or finding.get('url') or ''
            if endpoint and isinstance(endpoint, str):
                endpoints.append(endpoint)
        
        # Analyze endpoint structure
        if endpoints:
            # Extract path components and analyze patterns
            path_components = []
            for endpoint in endpoints:
                parts = endpoint.split('/')
                path_components.extend([p for p in parts if p])
            
            # Count common patterns
            pattern_counter = Counter(path_components)
            
            # Analyze versioning patterns
            version_pattern = re.compile(r'v[0-9]+|api/v[0-9]+|version[0-9]+', re.IGNORECASE)
            versioned_endpoints = [e for e in endpoints if version_pattern.search(e)]
            
            # Analyze REST compliance
            rest_patterns = {
                'collection': re.compile(r'/[a-zA-Z0-9_-]+s$'),
                'resource': re.compile(r'/[a-zA-Z0-9_-]+s/[a-zA-Z0-9_-]+$'),
                'action': re.compile(r'/[a-zA-Z0-9_-]+s/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$')
            }
            
            rest_compliance = {
                pattern_name: len([e for e in endpoints if pattern.search(e)])
                for pattern_name, pattern in rest_patterns.items()
            }
            
            self.endpoint_patterns = {
                'common_components': dict(pattern_counter.most_common(10)),
                'versioning': {
                    'versioned_count': len(versioned_endpoints),
                    'total_count': len(endpoints),
                    'percentage': len(versioned_endpoints) / len(endpoints) if endpoints else 0
                },
                'rest_compliance': rest_compliance
            }
    
    def analyze_developer_signatures(self, findings: List[Dict]):
        """Analyze findings to extract developer signatures and coding patterns."""
        # Extract code snippets or payloads from findings
        code_snippets = []
        for finding in findings:
            # Extract from evidence or payload fields
            evidence = finding.get('evidence', {})
            if isinstance(evidence, dict):
                if 'code' in evidence:
                    code_snippets.append(evidence['code'])
                if 'payload' in evidence:
                    code_snippets.append(evidence['payload'])
                if 'response_sample' in evidence:
                    code_snippets.append(evidence['response_sample'])
            
            # Extract from attack_pattern field
            attack_pattern = finding.get('attack_pattern')
            if attack_pattern and isinstance(attack_pattern, str):
                code_snippets.append(attack_pattern)
        
        # Analyze naming conventions
        naming_counts = defaultdict(int)
        for snippet in code_snippets:
            if not isinstance(snippet, str):
                continue
                
            for style, pattern in self.signature_patterns['naming_conventions'].items():
                matches = re.findall(pattern, snippet)
                naming_counts[style] += len(matches)
        
        # Analyze framework indicators
        for snippet in code_snippets:
            if not isinstance(snippet, str):
                continue
                
            for framework, patterns in self.framework_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, snippet):
                        self.framework_indicators[framework] += 1
        
        # Store developer signatures
        self.developer_signatures = {
            'naming_conventions': dict(naming_counts),
            'framework_indicators': dict(self.framework_indicators),
            'code_consistency': self.calculate_code_consistency(code_snippets)
        }
    
    def calculate_code_consistency(self, code_snippets: List[str]) -> Dict:
        """Calculate consistency metrics across code snippets."""
        if not code_snippets or not all(isinstance(s, str) for s in code_snippets):
            return {'consistency_score': 0, 'pattern_variance': 0}
        
        # Analyze indentation patterns
        indentation_patterns = defaultdict(int)
        for snippet in code_snippets:
            lines = snippet.split('\n')
            for line in lines:
                if line.strip():
                    # Count leading spaces
                    leading_spaces = len(line) - len(line.lstrip())
                    indentation_patterns[leading_spaces] += 1
        
        # Calculate variance in indentation
        if indentation_patterns:
            indentation_values = list(indentation_patterns.keys())
            if len(indentation_values) > 1:
                try:
                    pattern_variance = statistics.variance(indentation_values)
                except statistics.StatisticsError:
                    pattern_variance = 0
            else:
                pattern_variance = 0
                
            # Higher consistency = lower variance
            consistency_score = 1.0 / (1.0 + pattern_variance) if pattern_variance > 0 else 1.0
        else:
            consistency_score = 0
            pattern_variance = 0
        
        return {
            'consistency_score': consistency_score,
            'pattern_variance': pattern_variance,
            'indentation_patterns': dict(indentation_patterns)
        }
    
    def calculate_security_awareness(self, findings: List[Dict]) -> Dict:
        """Calculate security awareness metrics based on findings."""
        if not findings:
            return {
                'score': 0,
                'awareness_level': 'Unknown',
                'metrics': {}
            }
        
        # Count findings by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] += 1
        
        # Count findings by type
        type_counts = defaultdict(int)
        for finding in findings:
            vuln_type = finding.get('type', 'UNKNOWN')
            type_counts[vuln_type] += 1
        
        # Calculate security awareness score
        # Lower score = more severe findings = less security awareness
        total_findings = len(findings)
        weighted_score = 0
        
        # Severity weights
        weights = {
            'CRITICAL': 0.0,
            'HIGH': 0.25,
            'MEDIUM': 0.5,
            'LOW': 0.75,
            'INFO': 1.0,
            'UNKNOWN': 0.5
        }
        
        for severity, count in severity_counts.items():
            weight = weights.get(severity, 0.5)
            weighted_score += (weight * count)
        
        # Normalize score to 0-1 range
        awareness_score = weighted_score / total_findings if total_findings > 0 else 0
        
        # Categorize awareness level
        if awareness_score >= 0.8:
            awareness_level = 'Excellent'
        elif awareness_score >= 0.6:
            awareness_level = 'Good'
        elif awareness_score >= 0.4:
            awareness_level = 'Moderate'
        elif awareness_score >= 0.2:
            awareness_level = 'Poor'
        else:
            awareness_level = 'Critical'
        
        return {
            'score': awareness_score,
            'awareness_level': awareness_level,
            'metrics': {
                'severity_distribution': dict(severity_counts),
                'vulnerability_distribution': dict(type_counts),
                'total_findings': total_findings
            }
        }
    
    def extract_team_structure_insights(self, findings: List[Dict]) -> Dict:
        """Extract insights about team structure based on code patterns and consistency."""
        # Group findings by endpoints to analyze consistency across API areas
        endpoints_by_pattern = defaultdict(list)
        
        for finding in findings:
            endpoint = finding.get('endpoint') or finding.get('url') or ''
            if not endpoint or not isinstance(endpoint, str):
                continue
                
            # Extract API area (first path component after host)
            path_parts = endpoint.split('/')
            if len(path_parts) > 1:
                api_area = path_parts[1] if path_parts[1] else 'root'
                endpoints_by_pattern[api_area].append(finding)
        
        # Analyze consistency within each API area
        area_consistency = {}
        for area, area_findings in endpoints_by_pattern.items():
            # Extract code snippets from this area
            area_snippets = []
            for finding in area_findings:
                evidence = finding.get('evidence', {})
                if isinstance(evidence, dict):
                    if 'code' in evidence:
                        area_snippets.append(evidence['code'])
                    if 'payload' in evidence:
                        area_snippets.append(evidence['payload'])
            
            # Calculate consistency for this area
            area_consistency[area] = self.calculate_code_consistency(area_snippets)
        
        # Determine if patterns suggest multiple developers/teams
        consistency_scores = [data['consistency_score'] for data in area_consistency.values() if 'consistency_score' in data]
        
        # Calculate variance between different API areas
        if len(consistency_scores) > 1:
            try:
                area_variance = statistics.variance(consistency_scores)
            except statistics.StatisticsError:
                area_variance = 0
        else:
            area_variance = 0
        
        # High variance suggests multiple teams/developers
        team_structure_assessment = 'single_team'
        if area_variance > 0.3:  # Threshold for suggesting multiple teams
            team_structure_assessment = 'multiple_teams'
        elif area_variance > 0.15:  # Threshold for suggesting multiple developers
            team_structure_assessment = 'multiple_developers'
        
        return {
            'team_structure_assessment': team_structure_assessment,
            'area_variance': area_variance,
            'area_consistency': area_consistency,
            'dominant_naming_convention': self.get_dominant_naming_convention(),
            'framework_consistency': self.analyze_framework_consistency()
        }
    
    def get_dominant_naming_convention(self) -> Dict:
        """Determine the dominant naming convention used in the codebase."""
        if not self.developer_signatures or 'naming_conventions' not in self.developer_signatures:
            return {'dominant': 'unknown', 'consistency': 0}
        
        naming_counts = self.developer_signatures['naming_conventions']
        if not naming_counts:
            return {'dominant': 'unknown', 'consistency': 0}
        
        # Find the most common naming convention
        total = sum(naming_counts.values())
        if total == 0:
            return {'dominant': 'unknown', 'consistency': 0}
        
        dominant = max(naming_counts.items(), key=lambda x: x[1])
        consistency = dominant[1] / total if total > 0 else 0
        
        return {
            'dominant': dominant[0],
            'consistency': consistency,
            'distribution': {k: v/total for k, v in naming_counts.items()}
        }
    
    def analyze_framework_consistency(self) -> Dict:
        """Analyze consistency in framework usage across the codebase."""
        if not self.framework_indicators:
            return {'dominant': 'unknown', 'consistency': 0}
        
        total = sum(self.framework_indicators.values())
        if total == 0:
            return {'dominant': 'unknown', 'consistency': 0}
        
        # Find the most commonly detected framework
        dominant = max(self.framework_indicators.items(), key=lambda x: x[1]) if self.framework_indicators else ('unknown', 0)
        consistency = dominant[1] / total if total > 0 else 0
        
        return {
            'dominant': dominant[0],
            'consistency': consistency,
            'distribution': {k: v/total for k, v in self.framework_indicators.items()}
        }
    
    def analyze_log(self, input_log: str) -> str:
        """Analyze security findings from input log file with enhanced context, relationships, and developer insights."""
        try:
            with open(input_log, 'r') as f:
                findings = json.loads(f.read())

            # Update relationships between findings
            self.update_relationships(findings)
            
            # Extract endpoint patterns
            self.extract_endpoint_patterns(findings)
            
            # Analyze developer signatures
            self.analyze_developer_signatures(findings)
            
            # Calculate security awareness
            security_awareness = self.calculate_security_awareness(findings)
            
            # Extract team structure insights
            team_structure = self.extract_team_structure_insights(findings)

            # Group findings by vulnerability type
            findings_by_type = {}
            for finding in findings:
                vuln_type = finding.get('type')
                if vuln_type not in findings_by_type:
                    findings_by_type[vuln_type] = []
                findings_by_type[vuln_type].append(finding)
            
            analysis_results = {
                'security_analysis': {},
                'developer_insights': {
                    'security_awareness': security_awareness,
                    'team_structure': team_structure,
                    'api_design_patterns': self.endpoint_patterns,
                    'developer_signatures': self.developer_signatures
                }
            }
            
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

                6. Developer Behavior Analysis:
                   - Coding patterns that contributed to vulnerability
                   - Security awareness indicators
                   - Potential training opportunities

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
                analysis_results['security_analysis'][vuln_type] = {
                    'analysis': response.message.content,
                    'context': self.build_context(type_findings[0]),
                    'relationships': [self.relationship_graph.get(f['id'], []) for f in type_findings],
                    'remediation_template': self.remediation_templates.get(vuln_type, [])
                }
            
            return json.dumps(analysis_results, indent=2)

        except Exception as e:
            return f"Error analyzing log: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='Enhanced API security findings analyzer with developer behavior insights')
    parser.add_argument('--input', required=True, help='Input log file containing security findings')
    parser.add_argument('--output', required=True, help='Output file for analysis results')
    parser.add_argument('--model', default='llama3.3', help='LLM model name to use')
    parser.add_argument('--report-format', choices=['json', 'html', 'md'], default='json', help='Output report format')
    
    args = parser.parse_args()
    
    analyzer = EnhancedAPILogAnalyzer(model_name=args.model)
    analysis = analyzer.analyze_log(args.input)
    
    # Generate output in the specified format
    if args.report_format == 'json':
        output_content = analysis
    elif args.report_format == 'html':
        # Convert JSON to HTML report
        try:
            analysis_data = json.loads(analysis)
            html_content = ["<html><head><title>Enhanced API Security Analysis</title>"]
            html_content.append("<style>body{font-family:Arial,sans-serif;margin:20px;} ")
            html_content.append(".section{margin-bottom:20px;padding:10px;border:1px solid #ddd;} ")
            html_content.append(".high{color:red;} .medium{color:orange;} .low{color:green;} ")
            html_content.append("table{border-collapse:collapse;width:100%;} ")
            html_content.append("th,td{border:1px solid #ddd;padding:8px;text-align:left;} ")
            html_content.append("</style></head><body>")
            
            # Add developer insights section
            if 'developer_insights' in analysis_data:
                insights = analysis_data['developer_insights']
                html_content.append("<div class='section'><h2>Developer Insights</h2>")
                
                # Security awareness
                if 'security_awareness' in insights:
                    awareness = insights['security_awareness']
                    html_content.append(f"<h3>Security Awareness: {awareness.get('awareness_level', 'Unknown')}</h3>")
                    html_content.append(f"<p>Score: {awareness.get('score', 0):.2f}</p>")
                    
                    if 'metrics' in awareness:
                        html_content.append("<h4>Findings Distribution</h4><table>")
                        html_content.append("<tr><th>Severity</th><th>Count</th></tr>")
                        for severity, count in awareness['metrics'].get('severity_distribution', {}).items():
                            html_content.append(f"<tr><td>{severity}</td><td>{count}</td></tr>")
                        html_content.append("</table>")
                
                # Team structure
                if 'team_structure' in insights:
                    team = insights['team_structure']
                    html_content.append(f"<h3>Team Structure Assessment: {team.get('team_structure_assessment', 'Unknown').replace('_', ' ').title()}</h3>")
                    html_content.append(f"<p>Area Variance: {team.get('area_variance', 0):.2f}</p>")
                    
                    if 'dominant_naming_convention' in team:
                        naming = team['dominant_naming_convention']
                        html_content.append(f"<h4>Dominant Naming Convention: {naming.get('dominant', 'Unknown')}</h4>")
                        html_content.append(f"<p>Consistency: {naming.get('consistency', 0):.2f}</p>")
                
                html_content.append("</div>")
            
            # Add security analysis section
            if 'security_analysis' in analysis_data:
                html_content.append("<div class='section'><h2>Security Analysis</h2>")
                
                for vuln_type, data in analysis_data['security_analysis'].items():
                    html_content.append(f"<h3>{vuln_type}</h3>")
                    html_content.append(f"<div class='analysis'>{data.get('analysis', '').replace('\n', '<br>')}</div>")
                    
                    if 'remediation_template' in data and data['remediation_template']:
                        html_content.append("<h4>Remediation Steps</h4><ul>")
                        for step in data['remediation_template']:
                            html_content.append(f"<li>{step}</li>")
                        html_content.append("</ul>")
                
                html_content.append("</div>")
            
            html_content.append("</body></html>")
            output_content = '\n'.join(html_content)
        except json.JSONDecodeError:
            output_content = f"# Error in Analysis\n\n```\n{analysis}\n```"
    else:
        output_content = analysis
    
    # Write output to file
    with open(args.output, 'w') as f:
        f.write(output_content)
    
    print(f"Analysis complete. Results written to {args.output}")

if __name__ == '__main__':
    main()