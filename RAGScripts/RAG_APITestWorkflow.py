#!/usr/bin/env python3

import requests
import uuid
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger

class APITestWorkflowScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("api_test_workflow")

    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None,
             headers: Optional[Dict[str, str]] = None, tokens: Optional[Dict[str, List[Dict[str, Any]]]] = None,
             context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        
        findings = []
        correlation_id = str(uuid.uuid4())
        base_headers = {'Content-Type': 'application/json'}

        try:
            # Step 1: Get initial user list from debug endpoint
            debug_url = f"{url}/users/v1/_debug"
            initial_users_resp = requests.get(debug_url, timeout=5)
            initial_users = []

            if initial_users_resp.status_code == 200:
                initial_users = initial_users_resp.json().get('users', [])
                self.logger.info(f"Initial users count: {len(initial_users)}")

            # Step 2: Register new admin user
            register_url = f"{url}/users/v1/register"
            register_payload = {
                "admin": True,
                "username": "jimmy",
                "password": "jimmypass1",
                "email": "jimmy@admin.me"
            }

            register_resp = requests.post(
                register_url,
                json=register_payload,
                headers=base_headers,
                timeout=5
            )

            if register_resp.status_code == 200:
                self.logger.info("Successfully registered new admin user 'jimmy'")

                # Step 3: Verify user creation
                verify_resp = requests.get(debug_url, timeout=5)
                final_users = []

                if verify_resp.status_code == 200:
                    final_users = verify_resp.json().get('users', [])
                    new_user = next(
                        (u for u in final_users if u.get('username') == 'jimmy'),
                        None
                    )

                    if new_user:
                        self.logger.info("Verified new user 'jimmy' in user list")

                        # Step 4: Login as new user
                        login_url = f"{url}/users/v1/login"
                        login_payload = {
                            "username": "jimmy",
                            "password": "jimmypass1"
                        }

                        login_resp = requests.post(
                            login_url,
                            json=login_payload,
                            headers=base_headers,
                            timeout=5
                        )

                        if login_resp.status_code == 200:
                            auth_token = login_resp.json().get('auth_token')
                            if auth_token:
                                self.logger.info("Successfully obtained auth token")

                                # Create finding with complete evidence
                                findings.append({
                                    "type": "API_WORKFLOW_TEST",
                                    "severity": "INFO",
                                    "detail": "Successfully completed API workflow test",
                                    "evidence": {
                                        "initial_users": {
                                            "request": {
                                                "url": debug_url,
                                                "method": "GET",
                                                "headers": dict(initial_users_resp.request.headers)
                                            },
                                            "response": {
                                                "status_code": initial_users_resp.status_code,
                                                "headers": dict(initial_users_resp.headers),
                                                "body": initial_users_resp.json()
                                            }
                                        },
                                        "user_registration": {
                                            "request": {
                                                "url": register_url,
                                                "method": "POST",
                                                "headers": dict(register_resp.request.headers),
                                                "body": register_payload
                                            },
                                            "response": {
                                                "status_code": register_resp.status_code,
                                                "headers": dict(register_resp.headers),
                                                "body": register_resp.json()
                                            }
                                        },
                                        "verification": {
                                            "request": {
                                                "url": debug_url,
                                                "method": "GET",
                                                "headers": dict(verify_resp.request.headers)
                                            },
                                            "response": {
                                                "status_code": verify_resp.status_code,
                                                "headers": dict(verify_resp.headers),
                                                "body": verify_resp.json()
                                            }
                                        },
                                        "login": {
                                            "request": {
                                                "url": login_url,
                                                "method": "POST",
                                                "headers": dict(login_resp.request.headers),
                                                "body": login_payload
                                            },
                                            "response": {
                                                "status_code": login_resp.status_code,
                                                "headers": dict(login_resp.headers),
                                                "body": {"auth_token": auth_token}
                                            }
                                        },
                                        "correlation_id": correlation_id
                                    },
                                    "remediation": {
                                        "description": "API workflow test completed successfully",
                                        "steps": [
                                            "Monitor API endpoint access patterns",
                                            "Review user registration security controls",
                                            "Implement rate limiting for registration/login attempts",
                                            "Consider adding additional verification steps for admin user creation"
                                        ]
                                    }
                                })

        except requests.RequestException as e:
            self.logger.error(f"Error in API workflow test: {str(e)}")

        return findings

scan = APITestWorkflowScanner.scan