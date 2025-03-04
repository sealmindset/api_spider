import yaml
import json
import re
import argparse

def load_yaml_file(yaml_file_path):
    """Load and parse YAML file."""
    with open(yaml_file_path, 'r') as file:
        content = file.read().strip()
        # Remove leading/trailing whitespace and newlines
        if content.startswith('"swaggerDoc"'):
            # If the content starts with "swaggerDoc", assume it's a JSON-like format
            # Remove the outer wrapper and parse as YAML
            content = content.replace('"swaggerDoc":', '').strip()
            # Remove the trailing customOptions if present
            if ',\n  "customOptions"' in content:
                content = content.split(',\n  "customOptions"')[0]
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse YAML file: {e}")
        except Exception as e:
            raise ValueError(f"Failed to process file: {e}")

def convert_to_openapi3(swagger_obj):
    """Convert OpenAPI spec to version 3.0.1 format."""
    # No need to check for swaggerDoc wrapper as it's handled in load_yaml_file
    
    # Ensure OpenAPI version compatibility
    if swagger_obj.get('openapi', '').startswith(('3.1', '3.2')):
        swagger_obj['openapi'] = '3.0.1'  # Downgrade to 3.0.1 for better compatibility
        
    # Validate required OpenAPI fields
    if 'openapi' not in swagger_obj:
        raise ValueError("Missing 'openapi' field in specification")
    if 'info' not in swagger_obj:
        raise ValueError("Missing 'info' field in specification")
    if 'paths' not in swagger_obj:
        raise ValueError("Missing 'paths' field in specification")
        
    return swagger_obj

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert OpenAPI specification to version 3.0.1 format')
    parser.add_argument('--input', required=True, help='Input YAML file path')
    parser.add_argument('--output', required=True, help='Output YAML file path')
    args = parser.parse_args()
    
    try:
        # Load YAML file
        swagger_obj = load_yaml_file(args.input)
        
        # Convert to OpenAPI 3.0.1 format
        openapi_spec = convert_to_openapi3(swagger_obj)
        
        # Write to YAML file with proper formatting
        with open(args.output, 'w') as f:
            yaml.dump(openapi_spec, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
            
        print(f"Successfully converted {args.input} to OpenAPI 3.0.1 format")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    main()