#!/usr/bin/env python3

import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

class FindingFormatter:
    """Standardizes security findings across all scanners to ensure consistent output format
    for enhanced reporting.
    """
    
    def __init__(self):
        self.vulnerability_types = {
            'SQL_INJECTION': 'SQLi',
            'SQLI': 'SQLi',
            'BOLA': 'BOLA',
            'MASS_ASSIGNMENT': 'Mass Assignment',
            'DATA_EXPOSURE': 'Data Exposure',
            'CREDENTIAL_EXPOSURE': 'Data Exposure',
            'JWT_BYPASS': 'JWT Bypass',
            'RATE_LIMIT': 'Rate Limit',
            'REGEX_DOS': 'Regex DoS',
            'USER_PASS_ENUM': 'User/Pass Enumeration',
            'UNAUTHORIZED_PASSWORD_CHANGE': 'Unauthorized Password Change',
            'XSS': 'XSS',
            'SSRF': 'SSRF',
            'COMMAND_INJECTION': 'Command Injection',
            'PATH_TRAVERSAL': 'Path Traversal',
            'OPEN_REDIRECT': 'Open Redirect',
            'CORS': 'CORS Misconfiguration',
            'HOST_HEADER': 'Host Header Injection',
            'HTTP_METHOD': 'HTTP Method Abuse',
            'JWT': 'JWT Vulnerability',
            'USER_ENUM': 'User Enumeration'
        }
        
        self.severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    def format_finding(self, finding: Dict[str, Any], url: str = None, path: str = None) -> Dict[str, Any]:
        """Format a finding to match the enhanced finding format
        
        Args:
            finding: The original finding from a scanner
            url: Base URL of the target
            path: API endpoint path
            
        Returns:
            Dict[str, Any]: Standardized finding in enhanced format
        """
        # Generate a unique ID if not present
        if 'id' not in finding:
            finding_id = f"finding_{uuid.uuid4().hex[:8]}"
        else:
            finding_id = finding['id']
        
        # Normalize vulnerability type
        vuln_type = finding.get('type', 'UNKNOWN')
        normalized_type = self.vulnerability_types.get(vuln_type, vuln_type)
        
        # Extract or determine severity
        severity = finding.get('severity', 'MEDIUM')
        if severity not in self.severity_levels:
            severity = 'MEDIUM'
        
        # Extract endpoint information
        endpoint = finding.get('endpoint', path)
        if not endpoint and path:
            endpoint = path
        if url and endpoint and not endpoint.startswith(('http://', 'https://')):
            endpoint = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Extract parameter information
        parameter = finding.get('parameter')
        if not parameter and 'evidence' in finding:
            # Try to extract parameter from evidence
            evidence = finding['evidence']
            if isinstance(evidence, dict):
                if 'request' in evidence and isinstance(evidence['request'], dict):
                    # Try to extract from URL parameters or JSON body
                    if 'url' in evidence['request']:
                        url_str = evidence['request']['url']
                        param_match = re.search(r'[?&]([^=]+)=', url_str)
                        if param_match:
                            parameter = param_match.group(1)
                    elif 'body' in evidence['request'] and evidence['request']['body']:
                        # Try to extract first key from JSON body
                        try:
                            if isinstance(evidence['request']['body'], dict):
                                keys = list(evidence['request']['body'].keys())
                                if keys:
                                    parameter = keys[0]
                        except:
                            pass
        
        # Extract attack pattern
        attack_pattern = finding.get('attack_pattern')
        if not attack_pattern and 'evidence' in finding:
            evidence = finding['evidence']
            if isinstance(evidence, dict):
                if 'payload' in evidence:
                    attack_pattern = evidence['payload']
                elif 'request' in evidence and isinstance(evidence['request'], dict):
                    if 'body' in evidence['request'] and evidence['request']['body']:
                        attack_pattern = str(evidence['request']['body'])[:50]
        
        # Build standardized evidence object
        evidence = {}
        
        # Extract code snippet if available
        if 'evidence' in finding and isinstance(finding['evidence'], dict):
            if 'code' in finding['evidence']:
                evidence['code'] = finding['evidence']['code']
            elif 'vulnerable_code' in finding['evidence']:
                evidence['code'] = finding['evidence']['vulnerable_code']
        
        # Extract payload information
        if 'evidence' in finding and isinstance(finding['evidence'], dict):
            if 'payload' in finding['evidence']:
                evidence['payload'] = finding['evidence']['payload']
            elif 'attack_payload' in finding['evidence']:
                evidence['payload'] = finding['evidence']['attack_payload']
        
        # Extract response sample
        if 'evidence' in finding and isinstance(finding['evidence'], dict):
            if 'response' in finding['evidence'] and isinstance(finding['evidence']['response'], dict):
                if 'body' in finding['evidence']['response']:
                    evidence['response_sample'] = str(finding['evidence']['response']['body'])[:200]
            elif 'response_sample' in finding['evidence']:
                evidence['response_sample'] = finding['evidence']['response_sample']
        
        # If we don't have a code snippet, try to generate one based on the vulnerability type
        if 'code' not in evidence:
            evidence['code'] = self._generate_sample_code(normalized_type, parameter)
        
        # Ensure we have a payload
        if 'payload' not in evidence and attack_pattern:
            evidence['payload'] = attack_pattern
        
        # Ensure we have a response sample
        if 'response_sample' not in evidence:
            evidence['response_sample'] = '{"status":"error"}'
        
        # Build the standardized finding
        standardized_finding = {
            "id": finding_id,
            "type": normalized_type,
            "severity": severity,
            "endpoint": endpoint,
            "parameter": parameter,
            "attack_pattern": attack_pattern,
            "evidence": evidence,
            "detail": finding.get('detail', '')
        }
        
        return standardized_finding
    
    def _generate_sample_code(self, vuln_type: str, parameter: Optional[str] = None) -> str:
        """Generate sample vulnerable code based on vulnerability type
        
        Args:
            vuln_type: Type of vulnerability
            parameter: Parameter name if available
            
        Returns:
            str: Sample vulnerable code snippet
        """
        param = parameter if parameter else "input"
        
        code_samples = {
            'SQLi': f"const query = `SELECT * FROM users WHERE {param} = '${{user{param}}}'`;\ndb.execute(query);",
            'BOLA': f"app.get('/api/users/:id', (req, res) => {{\n  const userId = req.params.id;\n  const profile = getUserProfile(userId);\n  res.json(profile);\n}});",
            'Mass Assignment': f"function update(req, res) {{\n  const updates = req.body;\n  User.update(userId, updates);\n  res.json({{success: true}});\n}}",
            'Data Exposure': f"@app.route('/api/users/search')\ndef search_users():\n    query = request.args.get('{param}', '')\n    users = User.query.filter(User.username.contains(query)).all()\n    return jsonify([u.to_dict() for u in users])",
            'JWT Bypass': f"function verifyToken(token) {{\n  const decoded = jwt.verify(token, process.env.JWT_SECRET);\n  return decoded;\n}}",
            'Rate Limit': f"@app.route('/api/auth/login', methods=['POST'])\ndef login():\n    username = request.json.get('username')\n    password = request.json.get('password')\n    user = authenticate(username, password)\n    if user:\n        return jsonify(generate_token(user))\n    return jsonify({{'error': 'Invalid credentials'}}), 401",
            'Regex DoS': f"function validate{param.capitalize()}(input) {{\n  const regex = /^([a-zA-Z0-9])(([-._])?([a-zA-Z0-9]))*@([a-zA-Z0-9])(([-._])?([a-zA-Z0-9]))*\.[a-zA-Z]{{2,4}}$/;\n  return regex.test(input);\n}}",
            'User/Pass Enumeration': f"@Controller('/auth')\nexport class AuthController {{\n  @Post('/forgot-password')\n  async forgotPassword(@Body() body) {{\n    const user = await this.userService.findByEmail(body.email);\n    if (!user) {{\n      return {{ message: 'User not found' }};\n    }}\n    return {{ message: 'Password reset email sent' }};\n  }}\n}}",
            'Unauthorized Password Change': f"@RequestMapping(\"/users/change-password\")\npublic ResponseEntity<?> changePassword(@RequestParam(\"{param}\") Long userId, @RequestParam(\"new_password\") String newPassword) {{\n    userService.updatePassword(userId, newPassword);\n    return ResponseEntity.ok().build();\n}}",
            'XSS': f"app.get('/search', (req, res) => {{\n  const query = req.query.{param};\n  res.send(`<div>Search results for: ${{query}}</div>`);\n}});",
            'SSRF': f"app.post('/fetch', (req, res) => {{\n  const url = req.body.{param};\n  fetch(url).then(response => response.json()).then(data => res.json(data));\n}});",
            'Command Injection': f"app.get('/ping', (req, res) => {{\n  const host = req.query.{param};\n  exec(`ping -c 4 ${{host}}`, (error, stdout) => {{\n    res.send(stdout);\n  }});\n}});",
            'Path Traversal': f"app.get('/download', (req, res) => {{\n  const filename = req.query.{param};\n  res.sendFile(path.join(__dirname, 'files', filename));\n}});",
            'Open Redirect': f"app.get('/redirect', (req, res) => {{\n  const url = req.query.{param};\n  res.redirect(url);\n}});",
            'CORS Misconfiguration': f"app.use((req, res, next) => {{\n  res.header('Access-Control-Allow-Origin', '*');\n  res.header('Access-Control-Allow-Headers', '*');\n  next();\n}});",
            'Host Header Injection': f"app.get('/reset-password', (req, res) => {{\n  const host = req.headers.host;\n  sendResetEmail(email, `https://${{host}}/reset?token=${{token}}`);\n}});"
        }
        
        return code_samples.get(vuln_type, f"// Vulnerable code for {vuln_type}\nfunction process{param.capitalize()}(input) {{\n  // Implementation with security issue\n}}")