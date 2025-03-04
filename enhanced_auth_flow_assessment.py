#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
import requests
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.models import KnownModelName
from enum import Enum

from RAGScripts.auth_flow_scanner import AuthFlowScanner, setup_scanner_logger

# Pydantic models for structured data handling
class AuthType(str, Enum):
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "apikey"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    CUSTOM = "custom"

class TokenInfo(BaseModel):
    token_type: AuthType
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: Optional[int] = None
    scope: Optional[str] = None
    email: Optional[str] = None

class AuthenticationPattern(BaseModel):
    auth_type: AuthType
    token_location: str = Field(description="Where to place the token (header, query, body)")
    token_prefix: Optional[str] = None
    required_fields: List[str] = Field(default_factory=list)
    optional_fields: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)

class AuthenticationResult(BaseModel):
    success: bool
    token_info: Optional[TokenInfo] = None
    error: Optional[str] = None
    raw_response: Optional[Dict] = None

# AI Agent for dynamic authentication analysis
class AuthenticationAnalyzer:
    def __init__(self, model_name: str = KnownModelName.LLAMA_3_3):
        self.agent = Agent(model_name=model_name)
        self.logger = setup_scanner_logger("auth_analyzer")

    async def analyze_auth_pattern(self, swagger_spec: Dict) -> AuthenticationPattern:
        """Use LLaMA to analyze and detect authentication patterns from Swagger spec"""
        prompt = f"Analyze this API specification and identify the authentication pattern:\n{json.dumps(swagger_spec)}"
        
        response = await self.agent.analyze(
            prompt,
            context={
                "task": "auth_pattern_detection",
                "supported_auth_types": [auth_type.value for auth_type in AuthType]
            }
        )

        # Parse the AI response into structured pattern
        try:
            pattern_dict = json.loads(response.content)
            return AuthenticationPattern(**pattern_dict)
        except Exception as e:
            self.logger.error(f"Error parsing auth pattern: {str(e)}")
            return AuthenticationPattern(auth_type=AuthType.BEARER, token_location="header")

    async def generate_test_cases(self, auth_pattern: AuthenticationPattern) -> List[Dict]:
        """Generate dynamic test cases based on the detected authentication pattern"""
        prompt = f"Generate test cases for this authentication pattern:\n{auth_pattern.json()}"
        
        response = await self.agent.analyze(
            prompt,
            context={"task": "test_case_generation"}
        )

        try:
            return json.loads(response.content)
        except Exception as e:
            self.logger.error(f"Error generating test cases: {str(e)}")
            return []

class EnhancedAuthFlowScanner(AuthFlowScanner):
    def __init__(self, base_url: str, swagger_file: str, logger: Optional[logging.Logger] = None):
        super().__init__(base_url, swagger_file, logger)
        self.auth_analyzer = AuthenticationAnalyzer()
        self.auth_pattern = None
        self.test_cases = []

    async def initialize(self):
        """Initialize the scanner with AI-powered analysis"""
        self.auth_pattern = await self.auth_analyzer.analyze_auth_pattern(self.swagger_spec)
        self.test_cases = await self.auth_analyzer.generate_test_cases(self.auth_pattern)
        self.logger.info(f"Detected auth pattern: {self.auth_pattern.json()}")

    async def run_enhanced_assessment(self) -> Dict:
        """Run the enhanced authentication flow assessment"""
        await self.initialize()
        
        assessment_report = {
            'auth_pattern': self.auth_pattern.dict(),
            'test_cases': self.test_cases,
            'results': []
        }

        for test_case in self.test_cases:
            try:
                result = await self.execute_test_case(test_case)
                assessment_report['results'].append(result)
            except Exception as e:
                self.logger.error(f"Error executing test case: {str(e)}")

        return assessment_report

    async def execute_test_case(self, test_case: Dict) -> Dict:
        """Execute a single test case and return results"""
        try:
            # Execute the test case using the appropriate method based on the test type
            if test_case.get('type') == 'registration':
                return await self.execute_registration_test(test_case)
            elif test_case.get('type') == 'authentication':
                return await self.execute_authentication_test(test_case)
            elif test_case.get('type') == 'token_refresh':
                return await self.execute_token_refresh_test(test_case)
            else:
                return {'success': False, 'error': 'Unknown test case type'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

async def run_enhanced_assessment(base_url: str, swagger_file: str, output_file: str, verbosity: int = 1) -> Dict:
    """Run the enhanced API security assessment with AI-powered analysis"""
    logger = setup_scanner_logger("enhanced_auth_assessment")
    logger.setLevel(logging.DEBUG if verbosity > 1 else logging.INFO)
    
    logger.info(f"Starting Enhanced API Security Assessment on {base_url}")
    
    try:
        scanner = EnhancedAuthFlowScanner(base_url, swagger_file, logger)
        assessment_report = await scanner.run_enhanced_assessment()
        
        # Save the report
        with open(output_file, 'w') as f:
            json.dump(assessment_report, f, indent=2)
        
        logger.info(f"Assessment report saved to {output_file}")
        return assessment_report
        
    except Exception as e:
        logger.error(f"Error during enhanced assessment: {str(e)}")
        raise

async def main():
    parser = argparse.ArgumentParser(
        description='Enhanced API Security Assessment with AI-powered Authentication Flow Analysis'
    )
    parser.add_argument('--url', required=True, help='Base URL of the API to scan')
    parser.add_argument('--swagger', required=True, help='Path to Swagger/OpenAPI specification file')
    parser.add_argument('--output', default='enhanced_auth_assessment.json', 
                      help='Output file for assessment report')
    parser.add_argument('--model', default=KnownModelName.LLAMA_3_3,
                      help='LLM model to use for analysis')
    parser.add_argument('-v', '--verbose', action='count', default=1,
                      help='Increase verbosity level (-v, -vv, or -vvv)')
    
    args = parser.parse_args()
    
    try:
        await run_enhanced_assessment(args.url, args.swagger, args.output, args.verbose)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())