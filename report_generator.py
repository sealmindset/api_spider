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
                    <h3>{{ vuln_type }}</h3>
                    <div class="severity-badge" style="background-color: {{ data.severity_color }}">{{ data.severity }}</div>
                    
                    <div class="mt-3">
                        <h4>Analysis</h4>
                        <p>{{ data.analysis }}</p>
                    </div>

                    <div class="mt-3">
                        <h4>Technical Details</h4>
                        <div class="technical-details">
                            <pre>{{ data.technical_details }}</pre>
                        </div>
                    </div>

                    <div class="mt-3">
                        <h4>Remediation Steps</h4>
                        <ul>
                            {% for step in data.remediation_steps %}
                            <li>{{ step }}</li>
                            {% endfor %}
                        </ul>
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

        for vuln_type, data in findings.items():
            severity = self.determine_severity(data)
            total_findings += 1
            if severity == 'CRITICAL':
                critical_findings += 1

            processed_findings[vuln_type] = {
                'severity': severity,
                'severity_color': self.severity_colors[severity],
                'analysis': data.get('analysis', ''),
                'technical_details': json.dumps(data, indent=2),
                'remediation_steps': data.get('remediation_template', [])
            }

        return processed_findings, total_findings, critical_findings

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