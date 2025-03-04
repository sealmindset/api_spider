#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
import requests
from typing import Dict, List, Any

from RAGScripts.auth_flow_scanner import AuthFlowScanner, setup_scanner_logger


def setup_logging(verbosity: int = 1) -> logging.Logger:
    """Configure logging based on verbosity level"""
    logger = logging.getLogger('auth_flow_assessment')
    
    # Set logging level based on verbosity
    if verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    elif verbosity >= 3:
        level = logging.DEBUG  # Maximum detail
    else:
        level = logging.WARNING
    
    # Configure handler with custom format
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    
    return logger


def access_user_profile_endpoints(scanner: AuthFlowScanner, token_info: Dict, logger: logging.Logger) -> Dict:
    """Access specific user profile endpoints using the access token"""
    if not token_info or "accessToken" not in token_info:
        logger.error("No valid access token available for accessing user profile endpoints")
        return {"success": False, "error": "No valid access token"}
    
    access_token = token_info["accessToken"]
    email = token_info.get("email")
    
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    # Define the specific endpoints we want to access
    user_endpoints = [
        "/users/me",
        "/users/me/subscription",
        "/users/me/device-info",
        "/users/me/personal-health-info"
    ]
    
    results = []
    
    for endpoint in user_endpoints:
        url = scanner.base_url + endpoint
        logger.info(f"Accessing user profile endpoint: {url}")
        
        try:
            response = requests.get(url, headers=headers)
            
            result = {
                "endpoint": endpoint,
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response": scanner._safe_parse_json(response) if response.status_code == 200 else {"error": response.text[:200]}
            }
            
            if response.status_code == 200:
                logger.info(f"Successfully accessed {endpoint}")
            else:
                logger.warning(f"Failed to access {endpoint}: {response.status_code}")
                
            results.append(result)
            
        except Exception as e:
            logger.error(f"Error accessing {endpoint}: {str(e)}")
            results.append({
                "endpoint": endpoint,
                "success": False,
                "error": str(e)
            })
    
    return {
        "success": any(result["success"] for result in results),
        "results": results
    }

def run_assessment(base_url: str, swagger_file: str, output_file: str, verbosity: int = 1, additional_swagger_files: List[str] = None) -> Dict:
    """Run the API security assessment and return the results"""
    logger = setup_logging(verbosity)
    
    logger.info(f"Starting API Security Assessment on {base_url}")
    logger.info(f"Using primary Swagger file: {swagger_file}")
    
    # Ensure the primary swagger file exists
    if not os.path.exists(swagger_file):
        logger.error(f"Primary Swagger file not found: {swagger_file}")
        sys.exit(1)
    
    # Check additional swagger files if provided
    if additional_swagger_files:
        for additional_file in additional_swagger_files:
            if not os.path.exists(additional_file):
                logger.error(f"Additional Swagger file not found: {additional_file}")
                sys.exit(1)
            logger.info(f"Using additional Swagger file: {additional_file}")
    
    try:
        # Initialize the scanner with the primary swagger file and additional swagger files
        scanner = AuthFlowScanner(base_url, swagger_file, logger, additional_swagger_files)
        
        # Run the assessment
        assessment_report = scanner.run_assessment()
        
        # Access user profile endpoints if authentication was successful
        if assessment_report['authentication']['success']:
            logger.info("Accessing user profile endpoints")
            token_info = scanner.tokens.get(list(scanner.tokens.keys())[0]) if scanner.tokens else {}
            user_profile_results = access_user_profile_endpoints(scanner, token_info, logger)
            assessment_report['user_profile_access'] = user_profile_results
        else:
            assessment_report['user_profile_access'] = {
                "success": False,
                "error": "Authentication failed"
            }
        
        # Save the report
        with open(output_file, 'w') as f:
            json.dump(assessment_report, f, indent=2)
        
        logger.info(f"Assessment report saved to {output_file}")
        
        # Print summary
        print("\nAPI Security Assessment Summary:")
        print(f"Initial account creation: {'Success' if assessment_report['initial_account']['success'] else 'Failed'}")
        print(f"Rate limiting test: {len(assessment_report['rate_limiting']['findings'])} findings")
        print(f"Account verification: {assessment_report['account_verification']['success_count']} of {len(assessment_report['account_verification']['results'])} accounts verified")
        print(f"Authentication: {'Success' if assessment_report['authentication']['success'] else 'Failed'}")
        
        if assessment_report['authentication']['success']:
            print(f"Authenticated requests: {assessment_report['authenticated_requests']['success_count']} of {len(assessment_report['authenticated_requests']['results'])} successful")
            print(f"Token refresh: {'Success' if assessment_report['token_refresh']['success'] else 'Failed'}")
            print(f"User profile access: {'Success' if assessment_report['user_profile_access']['success'] else 'Failed'}")
            if assessment_report['user_profile_access']['success']:
                successful_endpoints = sum(1 for result in assessment_report['user_profile_access']['results'] if result['success'])
                total_endpoints = len(assessment_report['user_profile_access']['results'])
                print(f"User profile endpoints accessed: {successful_endpoints} of {total_endpoints} successful")
        
        print(f"Total findings: {len(assessment_report['findings'])}")
        
        return assessment_report
        
    except Exception as e:
        logger.error(f"Error during assessment: {str(e)}")
        raise


def main():
    parser = argparse.ArgumentParser(description='API Security Assessment for Account Creation, Rate Limiting, and Authentication Flow')
    parser.add_argument('--url', default='http://localhost:3000/api/v1/mobile', 
                        help='Base URL of the API to scan')
    parser.add_argument('--swagger', default='swagger/snorefox.yml', 
                        help='Path to primary Swagger/OpenAPI specification file')
    parser.add_argument('--additional-swagger', nargs='+', 
                        help='Additional Swagger/OpenAPI specification files (e.g., swagger/openapi3.yml)')
    parser.add_argument('--output', default='auth_flow_assessment.json', 
                        help='Output file for assessment report')
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        help='Increase verbosity level (-v, -vv, or -vvv)')
    
    args = parser.parse_args()
    
    try:
        run_assessment(args.url, args.swagger, args.output, args.verbose, args.additional_swagger)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()