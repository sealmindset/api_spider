#!/usr/bin/env python3

from typing import Dict, Optional, List
import logging
from ..utils.logger import setup_logger

class AuthHandler:
    def __init__(self):
        self.logger = setup_logger('auth_handler')

    def extract_security_schemes(self, spec: Dict) -> Dict:
        """Extract security schemes from OpenAPI spec"""
        security_schemes = {}
        try:
            components = spec.get('components', {})
            if 'securitySchemes' in components:
                security_schemes = components['securitySchemes']
            elif 'security' in spec:
                # Handle top-level security field
                security_schemes = spec['security']
        except Exception as e:
            self.logger.error(f"Error extracting security schemes: {str(e)}")
        return security_schemes

    def generate_auth_headers(self, security_schemes: Dict, token: Optional[str] = None) -> Dict[str, str]:
        """Generate authentication headers based on security schemes"""
        headers = {}
        try:
            for scheme_name, scheme in security_schemes.items():
                scheme_type = scheme.get('type', '').lower()
                
                if scheme_type == 'http':
                    scheme_scheme = scheme.get('scheme', '').lower()
                    if scheme_scheme == 'bearer' and token:
                        headers['Authorization'] = f'Bearer {token}'
                    elif scheme_scheme == 'basic' and token:
                        headers['Authorization'] = f'Basic {token}'
                
                elif scheme_type == 'apikey':
                    if token:
                        in_field = scheme.get('in')
                        if in_field == 'header':
                            name = scheme.get('name', 'X-API-Key')
                            headers[name] = token
                
                elif scheme_type == 'oauth2':
                    if token:
                        headers['Authorization'] = f'Bearer {token}'
                
                elif scheme_type == 'openidconnect':
                    if token:
                        headers['Authorization'] = f'Bearer {token}'

        except Exception as e:
            self.logger.error(f"Error generating auth headers: {str(e)}")
        
        return headers

    def get_endpoint_security(self, spec: Dict, path: str, method: str) -> List[Dict]:
        """Get security requirements for specific endpoint"""
        try:
            path_obj = spec.get('paths', {}).get(path, {})
            method_obj = path_obj.get(method.lower(), {})
            
            # Check method-level security first, then path-level, then global
            security = method_obj.get('security') or \
                      path_obj.get('security') or \
                      spec.get('security', [])
            
            return security
        except Exception as e:
            self.logger.error(f"Error getting endpoint security: {str(e)}")
            return []