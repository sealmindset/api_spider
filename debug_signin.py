#!/usr/bin/env python3

import yaml
import json
import sys
from RAGScripts.auth_flow_scanner import AuthFlowScanner

# Initialize the scanner with the same parameters
scanner = AuthFlowScanner('http://localhost:3000/api/v1/mobile', 'swagger/snorefox.yml')

# Try to find the sign-in endpoint
print('\nLooking for sign-in endpoint...')
sign_in_endpoint = scanner._find_endpoint_by_tag_and_summary('Authentication', ['sign-in'])
print(f'Sign-in endpoint found: {sign_in_endpoint}')

# Debug the _find_endpoint_by_tag_and_summary method for sign-in
print('\nDebugging endpoint search for "sign-in":')
for path, methods in scanner.endpoints.items():
    for method, details in methods.items():
        if 'Authentication' in details['tags']:
            summary = details['summary'].lower()
            description = details.get('description', '').lower()
            normalized_summary = summary.replace('-', ' ').replace('_', ' ')
            normalized_description = description.replace('-', ' ').replace('_', ' ')
            print(f'  Endpoint: {path} [{method}]')
            print(f'    Summary: "{summary}"')
            print(f'    Description: "{description}"')
            print(f'    Normalized Summary: "{normalized_summary}"')
            print(f'    Normalized Description: "{normalized_description}"')
            print(f'    Contains "sign-in": {"sign-in" in normalized_summary or "sign-in" in normalized_description}')
            
            # Check for variations
            variations = ['signin', 'sign in', 'login', 'log in']
            variation_matches = [var for var in variations if var in normalized_summary or var in normalized_description]
            print(f'    Variation matches: {variation_matches}')

# Test the full authentication flow
print('\nTesting full authentication flow:')
# 1. Register an account
print('\n1. Registering test account...')
initial_account = scanner.register_initial_account()
print(f'Registration result: {json.dumps(initial_account, indent=2) if initial_account else "Failed"}')

# 2. Authenticate with the created account
if initial_account:
    print('\n2. Authenticating with created account...')
    token_info = scanner.authenticate_account(initial_account)
    print(f'Authentication result: {"Success" if token_info else "Failed"}')
    if token_info:
        print(f'Tokens received: {list(token_info.keys())}')
else:
    print('Cannot authenticate - no account created')