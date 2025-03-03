#!/usr/bin/env python3

import logging
import time
import os
import json
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('llm_analyzer')

# Try to import ollama, with graceful fallback if not available
try:
    from ollama import chat
    OLLAMA_AVAILABLE = True
    logger.info("Ollama module successfully imported")
except ImportError:
    OLLAMA_AVAILABLE = False
    logger.warning("Ollama module not available. Using fallback mode.")

class LLMAnalyzer:
    def __init__(self, model_name='llama3.3', timeout=30):
        self.model_name = model_name
        self.timeout = timeout
        self.messages = []
        self.logger = logger
        
        # Check if Ollama is available
        if OLLAMA_AVAILABLE:
            self.logger.info(f"LLM Analyzer initialized with model: {model_name}")
        else:
            self.logger.warning("Running in fallback mode without Ollama")

    def analyze(self, query: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Analyze a security-related query with context and maintain chat history."""
        start_time = time.time()
        self.logger.info(f"Starting LLM analysis with model {self.model_name}")

        try:
            if not OLLAMA_AVAILABLE:
                raise ImportError("Ollama module not available")
                
            if context:
                # Format context for better LLM understanding
                context_str = "\n".join([f"{k}: {v}" for k, v in context.items()])
                query = f"Context:\n{context_str}\n\nQuery: {query}"

            self.logger.debug(f"Sending query to LLM: {query[:200]}...")
            self.messages.append({
                'role': 'user',
                'content': query
            })

            # Get response from the model with timeout
            response = chat(
                self.model_name,
                messages=self.messages,
                options={'timeout': self.timeout}
            )

            # Log successful response
            elapsed_time = time.time() - start_time
            self.logger.info(f"LLM analysis completed in {elapsed_time:.2f} seconds")

            # Add the assistant's response to messages
            self.messages.append({
                'role': 'assistant',
                'content': response.message.content
            })

            return response.message.content

        except Exception as e:
            elapsed_time = time.time() - start_time
            self.logger.error(f"LLM analysis failed after {elapsed_time:.2f} seconds: {str(e)}")
            
            # Provide fallback content
            fallback_content = self._generate_fallback_content(query)
            self.logger.info("Using fallback content due to LLM failure")
            return fallback_content

    def clear_history(self):
        """Clear the chat history."""
        self.messages = []

    def get_history(self) -> List[Dict[str, str]]:
        """Get the current chat history."""
        return self.messages

    def _generate_fallback_content(self, query: str) -> str:
        """Generate fallback content when LLM analysis fails."""
        # Determine the type of analysis being requested
        analysis_type = self._determine_analysis_type(query)
        
        # Basic template-based fallback content
        fallback_templates = {
            "vulnerability_analysis": """# Vulnerability Analysis

This finding indicates a potential security vulnerability that should be investigated further. Based on standard security practices, this type of issue could allow attackers to gain unauthorized access or extract sensitive information.

## Technical Impact

The vulnerability could potentially lead to:
- Unauthorized data access
- System compromise
- Information disclosure
- Privilege escalation

## Business Impact

- Potential data breaches
- Regulatory compliance issues
- Reputational damage
- Financial losses from remediation and penalties

## Remediation Steps

1. Review and validate all input parameters
2. Implement proper access controls
3. Add appropriate input validation
4. Follow security best practices for the affected component
5. Conduct thorough testing after implementing fixes""",
            
            "executive_summary": """# Executive Summary

This security assessment has identified several vulnerabilities that require attention. The findings represent various risk levels that should be addressed according to their severity.

## Key Risk Areas

- Input validation weaknesses
- Authentication and authorization flaws
- Sensitive data exposure
- Security misconfiguration

## Recommendations

1. Address critical and high severity findings immediately
2. Implement a security review process for code changes
3. Conduct regular security training for development teams
4. Establish a vulnerability management program
5. Perform regular security testing

## Prioritization

Focus remediation efforts on vulnerabilities that:
1. Have direct exposure to untrusted users
2. Affect sensitive data or critical functionality
3. Are easily exploitable with known attack methods""",
            
            "developer_insights": """# Developer Insights

## Root Cause Analysis

This vulnerability likely stems from common development patterns that prioritize functionality over security, such as:
- Direct use of user input without validation
- Lack of parameterization in database queries
- Insufficient access control checks

## Common Mistakes

- Trusting client-side validation only
- Using string concatenation with user input
- Implementing custom security mechanisms instead of proven libraries
- Insufficient error handling and logging

## Secure Coding Patterns

1. Always validate and sanitize all inputs
2. Use parameterized queries for database operations
3. Implement proper authentication and authorization checks
4. Apply the principle of least privilege
5. Use secure defaults and fail securely

## Testing Strategies

- Implement unit tests for security controls
- Conduct regular code reviews with security focus
- Use automated security scanning tools
- Perform penetration testing on critical components"""
        }
        
        return fallback_templates.get(analysis_type, fallback_templates["vulnerability_analysis"])
    
    def _determine_analysis_type(self, query: str) -> str:
        """Determine the type of analysis being requested based on the query content."""
        query = query.lower()
        
        if "executive summary" in query or "overview" in query:
            return "executive_summary"
        elif "developer" in query or "code" in query or "root cause" in query:
            return "developer_insights"
        else:
            return "vulnerability_analysis"

# Convenience function for direct chat access
def chat_with_llm(model_name, messages, timeout=30):
    """Simplified interface for chatting with the LLM."""
    if not OLLAMA_AVAILABLE:
        logger.warning("Ollama not available, using fallback response")
        return type('obj', (object,), {
            'message': type('obj', (object,), {
                'content': "Ollama is not available. Please install Ollama to use LLM features."
            })
        })
        
    try:
        return chat(model_name, messages=messages, options={'timeout': timeout})
    except Exception as e:
        logger.error(f"Error in chat_with_llm: {str(e)}")
        return type('obj', (object,), {
            'message': type('obj', (object,), {
                'content': f"Error communicating with LLM: {str(e)}"
            })
        })