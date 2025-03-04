#!/usr/bin/env python3

import yaml
import json
import sys
from RAGScripts.auth_flow_scanner import AuthFlowScanner

# Initialize the scanner with the same parameters
scanner = AuthFlowScanner('http://localhost:3000/api/v1/mobile', 'swagger/snorefox.yml')

# Print the loaded Swagger spec paths
print('\nSwagger spec paths:')
for path in scanner.swagger_spec.get('paths', {}).keys():
    print(f'  {path}')

# Print the extracted endpoints
print('\nExtracted endpoints:')
for path in scanner.endpoints.keys():
    print(f'  {path}')

# Print all authentication endpoints
print('\nAuthentication endpoints in Swagger:')
for path, methods in scanner.swagger_spec.get('paths', {}).items():
    for method, details in methods.items():
        if isinstance(details, dict) and 'tags' in details and 'Authentication' in details['tags']:
            print(f'  {path} [{method}] - {details.get("summary", "")}')

# Try to find the registration endpoint
print('\nLooking for registration endpoint...')
register_endpoint = scanner._find_endpoint_by_tag_and_summary('Authentication', ['sign-up'])
print(f'Register endpoint found: {register_endpoint}')

# Debug the _find_endpoint_by_tag_and_summary method
print('\nDebugging endpoint search for "sign-up":')
for path, methods in scanner.endpoints.items():
    for method, details in methods.items():
        if 'Authentication' in details['tags']:
            summary = details['summary'].lower()
            normalized_summary = summary.replace('-', ' ')
            print(f'  Endpoint: {path} [{method}]')
            print(f'    Summary: "{summary}"')
            print(f'    Normalized: "{normalized_summary}"')
            print(f'    Contains "sign-up": {"sign-up" in normalized_summary}')
            print(f'    Contains "sign" and "up": {"sign" in normalized_summary and "up" in normalized_summary}')