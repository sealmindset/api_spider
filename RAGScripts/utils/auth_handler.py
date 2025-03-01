#!/usr/bin/env python3

from typing import Dict, Optional, List
import logging
import time
from ..utils.logger import setup_logger

class AuthHandler:
    def __init__(self):
        self.logger = setup_logger('auth_handler')
        self.auth_states = {}
        self.tokens = {}
        self.token_expiry = {}
        self.refresh_tokens = {}
        self.active_auth_methods = {}
        self.last_auth_change = None
        self.auth_history = []
        self.token_refresh_attempts = {}
        self.auth_method_priorities = {
            'bearer': 1,
            'oauth2': 2,
            'openidconnect': 3,
            'basic': 4,
            'apikey': 5
        }

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

    def track_auth_state(self, endpoint: str, method: str, auth_method: str, token: str) -> None:
        """Track authentication state changes for an endpoint"""
        state_key = f"{method.upper()}:{endpoint}"
        current_time = time.time()
        
        # Record the authentication state change
        state = {
            'auth_method': auth_method,
            'token': token,
            'timestamp': current_time,
            'endpoint': endpoint,
            'method': method.upper(),
            'success': True
        }
        
        self.auth_states[state_key] = state
        self.auth_history.append(state)
        self.last_auth_change = current_time
        
        # Update active auth methods
        if auth_method not in self.active_auth_methods:
            self.active_auth_methods[auth_method] = []
        if endpoint not in self.active_auth_methods[auth_method]:
            self.active_auth_methods[auth_method].append(endpoint)

    def refresh_token(self, auth_method: str) -> Optional[str]:
        """Attempt to refresh an expired token with rate limiting and retry tracking"""
        try:
            current_time = time.time()
            
            # Check refresh rate limiting
            if auth_method in self.token_refresh_attempts:
                last_attempt = self.token_refresh_attempts[auth_method].get('last_attempt', 0)
                attempts = self.token_refresh_attempts[auth_method].get('attempts', 0)
                
                # Rate limit: max 3 attempts per minute
                if current_time - last_attempt < 60 and attempts >= 3:
                    self.logger.warning(f"Token refresh rate limit hit for {auth_method}")
                    return None
                    
                # Reset attempts counter after 5 minutes
                if current_time - last_attempt > 300:
                    attempts = 0
            
            if auth_method not in self.refresh_tokens:
                return None

            refresh_token = self.refresh_tokens[auth_method]
            new_token = self._perform_token_refresh(auth_method, refresh_token)
            
            # Update refresh attempts tracking
            self.token_refresh_attempts[auth_method] = {
                'last_attempt': current_time,
                'attempts': self.token_refresh_attempts.get(auth_method, {}).get('attempts', 0) + 1
            }
            
            if new_token:
                self.tokens[auth_method] = new_token
                self.token_expiry[auth_method] = current_time + 3600
                
                # Reset attempts on successful refresh
                self.token_refresh_attempts[auth_method]['attempts'] = 0
                return new_token
                
        except Exception as e:
            self.logger.error(f"Error refreshing token for {auth_method}: {str(e)}")
        return None

    def _perform_token_refresh(self, auth_method: str, refresh_token: str) -> Optional[str]:
        """Internal method to perform the actual token refresh"""
        # Implement specific refresh logic for different auth methods
        # This is a placeholder for actual implementation
        return None

    def is_token_expired(self, auth_method: str) -> bool:
        """Check if a token has expired"""
        if auth_method not in self.token_expiry:
            return True
        return time.time() > self.token_expiry[auth_method]

    def is_token_expired(self, auth_method: str) -> bool:
        """Check if a token has expired"""
        if auth_method not in self.token_expiry:
            return True
        return time.time() > self.token_expiry[auth_method]

    def generate_auth_headers(self, security_schemes: Dict, token: Optional[str] = None) -> Dict[str, str]:
        """Generate authentication headers based on security schemes"""
        headers = {}
        try:
            for scheme_name, scheme in security_schemes.items():
                scheme_type = scheme.get('type', '').lower()
                
                if scheme_type == 'http':
                    scheme_scheme = scheme.get('scheme', '').lower()
                    if scheme_scheme == 'bearer' and token:
                        if not self.is_token_expired('bearer'):
                            headers['Authorization'] = f'Bearer {token}'
                        else:
                            new_token = self.refresh_token('bearer')
                            if new_token:
                                headers['Authorization'] = f'Bearer {new_token}'
                    elif scheme_scheme == 'basic' and token:
                        if not self.is_token_expired('basic'):
                            headers['Authorization'] = f'Basic {token}'
                        else:
                            new_token = self.refresh_token('basic')
                            if new_token:
                                headers['Authorization'] = f'Basic {new_token}'
                
                elif scheme_type == 'apikey':
                    if token:
                        in_field = scheme.get('in')
                        if in_field == 'header':
                            name = scheme.get('name', 'X-API-Key')
                            if not self.is_token_expired('apikey'):
                                headers[name] = token
                            else:
                                new_token = self.refresh_token('apikey')
                                if new_token:
                                    headers[name] = new_token
                
                elif scheme_type == 'oauth2':
                    if token:
                        if not self.is_token_expired('oauth2'):
                            headers['Authorization'] = f'Bearer {token}'
                        else:
                            new_token = self.refresh_token('oauth2')
                            if new_token:
                                headers['Authorization'] = f'Bearer {new_token}'
                
                elif scheme_type == 'openidconnect':
                    if token:
                        if not self.is_token_expired('openidconnect'):
                            headers['Authorization'] = f'Bearer {token}'
                        else:
                            new_token = self.refresh_token('openidconnect')
                            if new_token:
                                headers['Authorization'] = f'Bearer {new_token}'

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