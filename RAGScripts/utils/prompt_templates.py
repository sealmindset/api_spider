SECURITY_ANALYSIS_TEMPLATE = """
Analyze the following API endpoint for security vulnerabilities:
Endpoint: {endpoint}
Method: {method}
Response: {response}

Consider:
1. Authentication/Authorization issues
2. Injection vulnerabilities
3. Data exposure risks
4. API misconfigurations
"""

BEHAVIOR_ANALYSIS_TEMPLATE = """
Analyze API behavior and patterns:
Endpoint: {endpoint}
Method: {method}
Response: {response}
"""

METHOD_ANALYSIS_TEMPLATE = """
Analyze HTTP method usage:
Endpoint: {endpoint}
Method: {method}
"""

class PromptTemplates:
    def __init__(self):
        self.templates = {
            "security_analysis": {
                "base": """
                Analyze the following API endpoint for security vulnerabilities:
                Endpoint: {endpoint}
                Method: {method}
                Response: {response}
                
                Consider:
                1. Authentication/Authorization issues
                2. Injection vulnerabilities
                3. Data exposure risks
                4. API misconfigurations
                """,
                
                "detailed": """
                Perform a comprehensive security analysis of:
                
                API Endpoint: {endpoint}
                HTTP Method: {method}
                Headers: {headers}
                Response Code: {status_code}
                Response Body: {response}
                
                Evaluate for:
                1. Authentication bypass possibilities
                2. Authorization flaws
                3. Injection vulnerabilities (SQL, NoSQL, Command)
                4. Sensitive data exposure
                5. Rate limiting issues
                6. Input validation weaknesses
                7. Security misconfigurations
                
                Provide findings in the following format:
                - Vulnerability Type
                - Severity (Critical/High/Medium/Low)
                - Description
                - Evidence
                - Remediation
                """
            },
            
            "vulnerability_check": {
                "auth_bypass": "Analyze authentication mechanisms for potential bypasses in: {endpoint}",
                "injection": "Check for {injection_type} injection vulnerabilities in: {endpoint}",
                "data_exposure": "Scan for sensitive data exposure in response from: {endpoint}",
                "rate_limit": "Test rate limiting implementation on: {endpoint}"
            }
        }
    
    def get_template(self, template_type: str, subtype: str = "base") -> str:
        """Get a specific prompt template"""
        return self.templates.get(template_type, {}).get(subtype, "")
    
    def format_template(self, template_type: str, subtype: str = "base", **kwargs) -> str:
        """Format a template with provided parameters"""
        template = self.get_template(template_type, subtype)
        return template.format(**kwargs) if template else ""