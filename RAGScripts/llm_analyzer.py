import logging
import time
from typing import Optional, Dict, List, Any
from ollama import chat
from .utils.logger import setup_scanner_logger

class LLMAnalyzer:
    def __init__(self, model_name='llama3.3', timeout=30):
        self.model_name = model_name
        self.timeout = timeout
        self.messages = []
        self.logger = setup_scanner_logger("llm_analyzer")

    def analyze(self, query: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Analyze a security-related query with context and maintain chat history."""
        start_time = time.time()
        self.logger.info(f"Starting LLM analysis with model {self.model_name}")

        try:
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
        # Basic template-based fallback content
        fallback_template = {
            "vulnerability_analysis": "Based on standard security practices, this finding indicates a potential security vulnerability that should be investigated further.",
            "impact_assessment": "The impact of this vulnerability could affect system security and should be evaluated based on the specific context.",
            "remediation_steps": [
                "Review and validate all input parameters",
                "Implement proper access controls",
                "Add appropriate input validation",
                "Follow security best practices for the affected component"
            ]
        }

        return f"""Analysis (Fallback Content):\n\n{fallback_template['vulnerability_analysis']}\n\n"""\
               f"Impact:\n{fallback_template['impact_assessment']}\n\n"""\
               f"Recommended Steps:\n" + "\n".join(f"- {step}" for step in fallback_template['remediation_steps'])