#!/usr/bin/env python3
"""
api_spider.py

A lightweight API crawler for discovering and documenting REST API endpoints.
It reads candidate endpoint paths from a dictionary file and generates permutations
to discover potential API endpoints.

Features:
1. Blind API endpoint discovery
2. Path parameter permutation testing
3. OpenAPI specification generation
"""

import re
import requests
from urllib.parse import urljoin
import sys
import yaml
import json
import argparse
from typing import Dict, List, Tuple, Any
import logging
import time
import os

def setup_logging(verbosity: int) -> logging.Logger:
    """Configure logging based on verbosity level"""
    logger = logging.getLogger('api_spider')
    
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

def parse_dict_file(filename):
    """Load dictionary file from current directory or absolute path"""
    sections = {}
    current_section = None
    
    try_paths = [
        filename,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    ]
    
    for try_path in try_paths:
        try:
            with open(try_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('//'):
                        continue
                        
                    if line.startswith('#'):
                        current_section = line.lstrip('#').strip()
                        if current_section not in sections:
                            sections[current_section] = []
                    else:
                        if current_section == "Parameter Values":
                            if "Common Values" not in sections:
                                sections["Common Values"] = []
                            sections["Common Values"].append(line)
                        elif current_section is not None:
                            sections[current_section].append(line)
                
                return sections
        except FileNotFoundError:
            continue
    
    print(f"Error: Dictionary file '{filename}' not found in current directory or as absolute path.")
    sys.exit(1)

def substitute_placeholders(path, candidate_values):
    """Replace path parameters with candidate values"""
    placeholders = re.findall(r'\{(\w+)\}', path)
    if not placeholders:
        return [path]
    else:
        param = placeholders[0]
        results = []
        for value in candidate_values:
            new_path = path.replace("{" + param + "}", value, 1)
            results.extend(substitute_placeholders(new_path, candidate_values))
        return results

def generate_candidate_urls(base_paths, candidate_values, base_url):
    """Generate URLs with parameter substitutions"""
    urls = set()
    
    for path in base_paths:
        if '{' in path:
            substituted_paths = substitute_placeholders(path, candidate_values)
            for sp in substituted_paths:
                full_url = urljoin(base_url, sp)
                urls.add((full_url, path))
        else:
            full_url = urljoin(base_url, path)
            urls.add((full_url, path))
    
    return list(urls)

def generate_base_paths(parameters: List[str], common_values: List[str], max_depth: int = 5) -> List[str]:
    """Generate base API paths"""
    paths = {'/'}
    
    # Define core components based on common API patterns
    # These are only used if no OpenAPI spec is provided
    core_paths = {}
    parameterized_paths = {}
    
    # Check if we have paths from an OpenAPI spec
    if isinstance(parameters, dict) and 'openapi_paths' in parameters and parameters['openapi_paths']:
        # Use paths from the OpenAPI spec
        for path in parameters['openapi_paths']:
            # Add the complete path directly to ensure we test exactly what's in the spec
            paths.add(path)
            
            # Also break down the path for structured exploration
            path_parts = path.strip('/').split('/')
            if len(path_parts) > 0:
                base = '/' + path_parts[0]
                if base not in core_paths:
                    core_paths[base] = []
                
                if len(path_parts) > 1:
                    core_paths[base].append(path_parts[1])
                    
                    # Handle path parameters
                    if '{' in path:
                        param_base = '/' + '/'.join(path_parts[:2])
                        if param_base not in parameterized_paths:
                            parameterized_paths[param_base] = []
                        
                        # Extract path parameters
                        for part in path_parts[2:]:
                            if '{' in part and '}' in part:
                                parameterized_paths[param_base].append(part)
    else:
        # No OpenAPI spec provided, use empty path structures
        # This ensures we don't use hardcoded paths that might interfere with proper scanning
        core_paths = {'/': []}
        parameterized_paths = {}
    
    def build_path_tree(base='/', depth=0):
        if depth >= max_depth:
            return
        
        paths.add(base)
        segments = core_paths.get(base, [])
        if depth == 0:
            segments.extend(core_paths['/'])
        
        for segment in segments:
            new_path = f"{base.rstrip('/')}/{segment}"
            paths.add(new_path)
            
            if depth + 1 < max_depth:
                build_path_tree(new_path, depth + 1)
        
        # Handle parameterized paths separately
        param_segments = parameterized_paths.get(base, [])
        for segment in param_segments:
            new_path = f"{base.rstrip('/')}/{segment}"
            paths.add(new_path)
            
            # Only add subresources if specifically needed
            if depth + 1 < max_depth and '{' in segment:
                # Limit subresources to common ones
                for subresource in ['email', 'password']:
                    subpath = f"{new_path}/{subresource}"
                    # Don't automatically add these - they'll be tested only if base path exists
                    paths.add(subpath)
    
    build_path_tree('/', 0)
    cleaned_paths = {re.sub('/+', '/', path) for path in paths}
    return list(cleaned_paths)

def crawl(base_url: str, token=None, logger=None) -> List[Tuple[str, str, str, int, Dict]]:
    """Discover API endpoints by crawling the base URL"""
    discovered = []
    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    logger.info("Starting crawl using permutations.txt...")
    
    try:
        with open('permutations.txt', 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error("permutations.txt not found")
        return discovered
    
    logger.info(f"Testing {len(paths)} paths...")
    
    for path in paths:
        # Skip paths with parameters if base endpoint doesn't exist
        if '{' in path:
            base_path = re.sub(r'\{[^}]+\}/.*', '', path)
            base_url_test = urljoin(base_url, base_path)
            try:
                response = requests.get(base_url_test, headers=headers, timeout=10)
                if response.status_code == 404:
                    logger.debug(f"Skipping parameter testing for non-existent base path: {base_path}")
                    continue
            except requests.RequestException:
                continue
        
        # Fix URL construction to prevent path duplication
        # Parse the base_url to get its path component
        from urllib.parse import urlparse
        parsed_base_url = urlparse(base_url)
        base_path = parsed_base_url.path.rstrip('/')
        
        # Check if the path is already in the base_url to avoid duplication
        if path.lstrip('/') in base_url.rstrip('/').split('/'):
            url = base_url
        else:
            # Remove any overlapping segments from the path
            path_parts = path.lstrip('/').split('/')
            base_path_parts = base_path.lstrip('/').split('/') if base_path else []
            
            # Find where path segments start to differ
            overlap_index = 0
            for i in range(min(len(base_path_parts), len(path_parts))):
                if base_path_parts[i] != path_parts[i]:
                    break
                overlap_index = i + 1
            
            # Construct URL using only non-overlapping segments
            if overlap_index > 0:
                unique_path = '/'.join(path_parts[overlap_index:])
                url = urljoin(base_url, unique_path)
            else:
                url = urljoin(base_url, path)
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                response_data = {"content": response.text}
            
            if response.status_code != 404:
                discovered.append((url, path, 'GET', response.status_code, response_data))
                logger.info(f"Discovered: GET {url} - Status: {response.status_code}")
                
                for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    try:
                        response = requests.request(method, url, headers=headers, timeout=10)
                        if response.status_code != 404:
                            try:
                                response_data = response.json()
                            except json.JSONDecodeError:
                                response_data = {"content": response.text}
                            discovered.append((url, path, method, response.status_code, response_data))
                            logger.info(f"Discovered: {method} {url} - Status: {response.status_code}")
                    except requests.RequestException:
                        continue
                        
        except requests.RequestException:
            logger.warning(f"Error accessing {url}")
            time.sleep(0.5)
            continue
    
    return discovered

def generate_openapi_spec(endpoints: List[Tuple[str, str, str, int, Dict]]) -> Dict:
    """Generate OpenAPI specification from discovered endpoints"""
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Discovered API",
            "version": "1.0.0",
            "description": "API specification generated by api_spider"
        },
        "paths": {}
    }
    
    for url, path_template, method, status_code, response_data in endpoints:
        if path_template not in spec["paths"]:
            spec["paths"][path_template] = {}
            
        spec["paths"][path_template][method.lower()] = {
            "summary": f"Discovered {method} endpoint",
            "responses": {
                str(status_code): {
                    "description": "Response",
                    "content": {
                        "application/json": {
                            "example": response_data
                        }
                    }
                }
            }
        }
        
        params = re.findall(r'\{(\w+)\}', path_template)
        if params:
            spec["paths"][path_template][method.lower()]["parameters"] = [
                {
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"}
                }
                for param in params
            ]
    
    return spec

def main():
    parser = argparse.ArgumentParser(description='API Spider - Discover and document REST API endpoints')
    parser.add_argument('--url', required=True, help='Base URL of the API to scan')
    parser.add_argument('--output', default='test.yml', help='Output file for OpenAPI specification (default: test.yml)')
    parser.add_argument('--dict', default='dict.txt', help='Dictionary file path (default: dict.txt)')
    parser.add_argument('--token', help='Bearer token for authorization')
    parser.add_argument('--depth', type=int, default=5, choices=range(1, 11),
                       help='Maximum depth for API crawling (1-10, default: 5)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help='Increase verbosity level (-v, -vv, or -vvv)')
    args = parser.parse_args()
    
    logger = setup_logging(args.verbose)
    base_url = args.url.rstrip('/')
    
    sections = parse_dict_file(args.dict)
    base_paths = sections.get("Base Paths", [])
    
    if not base_paths:
        logger.info("No predefined paths found, generating paths...")
        parameters = sections.get("Common Parameters", [])
        candidate_values = sections.get("Common Values", [])
        base_paths = generate_base_paths(parameters, candidate_values, args.depth)
        logger.info(f"Generated {len(base_paths)} potential paths")
    
    if not base_paths:
        print("Error: Could not generate base paths from parameters.")
        sys.exit(1)
    
    logger.info(f"Starting scan of {base_url}")
    discovered_endpoints = crawl(base_url, args.token, logger)
    
    print(f"\nTotal endpoints discovered: {len(discovered_endpoints)}")
    
    openapi_spec = generate_openapi_spec(discovered_endpoints)
    with open(args.output, 'w') as f:
        yaml.dump(openapi_spec, f, sort_keys=False)
    print(f"\nOpenAPI specification saved to {args.output}")

if __name__ == '__main__':
    main()
