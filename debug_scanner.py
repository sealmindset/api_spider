#!/usr/bin/env python3

import yaml
import json
import sys
from RAGScripts.auth_flow_scanner import AuthFlowScanner

# Initialize the scanner with the VAmPI swagger file
scanner = AuthFlowScanner('http://localhost:5002', 'swagger/openapi3.yml')

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
register_endpoint = scanner._find_endpoint_by_tag_and_summary('users', ['register'])
print(f'Register endpoint found: {register_endpoint is not None}')

# Debug the registration endpoint detection
print('\nDebugging registration endpoint detection:')
for path, methods in scanner.swagger_spec.get('paths', {}).items():
    if '/users/v1/register' in path:
        for method, details in methods.items():
            if method.lower() == 'post':
                print(f'  Found registration endpoint: {path} [{method}]')
                print(f'    Summary: "{details.get("summary", "")}"')
                print(f'    Tags: {details.get("tags", [])}"')
                if register_endpoint:
                    print(f'    Detected by scanner: Yes')
                    print(f'    Path: {register_endpoint["path"]}')
                    print(f'    Method: {register_endpoint["method"]}')
                else:
                    print(f'    Detected by scanner: No')

# Print details of the request body schema for the registration endpoint
if '/users/v1/register' in scanner.swagger_spec.get('paths', {}):
    register_details = scanner.swagger_spec['paths']['/users/v1/register']['post']
    if 'requestBody' in register_details:
        print('\nRegistration request body schema:')
        request_body = register_details['requestBody']
        if 'content' in request_body and 'application/json' in request_body['content']:
            schema = request_body['content']['application/json'].get('schema', {})
            print(f'  Schema: {schema}')
            if 'properties' in schema:
                print('  Properties:')
                for prop_name, prop_details in schema['properties'].items():
                    print(f'    {prop_name}: {prop_details.get("type", "unknown")} (example: {prop_details.get("example", "none")})')