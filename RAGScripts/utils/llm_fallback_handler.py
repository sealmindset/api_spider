import os
import logging
from typing import Dict, List, Optional, Union
from ollama import chat as ollama_chat

# Try to import OpenAI, but don't fail if it's not installed
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

class LLMFallbackHandler:
    """Handles fallback between different LLM providers (Ollama and OpenAI)"""
    
    def __init__(self, primary_model='llama3.3', fallback_model='gpt-4o', 
                 confidence_threshold=0.7, max_retries=2):
        """Initialize the LLM fallback handler.
        
        Args:
            primary_model: The name of the primary Ollama model to use
            fallback_model: The name of the OpenAI model to use as fallback
            confidence_threshold: Threshold below which to trigger fallback
            max_retries: Maximum number of retry attempts before falling back
        """
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        self.confidence_threshold = confidence_threshold
        self.max_retries = max_retries
        self.logger = logging.getLogger(__name__)
        
        # Check if OpenAI API key is available
        self.openai_api_key = os.environ.get('OPENAI_API_KEY')
        self.openai_enabled = OPENAI_AVAILABLE and self.openai_api_key is not None
        
        if not self.openai_enabled and OPENAI_AVAILABLE:
            self.logger.warning("OpenAI fallback is available but no API key found. Set OPENAI_API_KEY environment variable.")
        elif not OPENAI_AVAILABLE:
            self.logger.warning("OpenAI package not installed. Fallback to OpenAI will not be available.")
    
    def _extract_confidence(self, response_content: str) -> float:
        """Extract confidence score from LLM response.
        
        This is a simple heuristic that looks for confidence indicators in the text.
        A more sophisticated implementation could parse structured output.
        
        Args:
            response_content: The text response from the LLM
            
        Returns:
            Estimated confidence score between 0 and 1
        """
        # Look for explicit confidence indicators
        confidence_indicators = [
            "high confidence", "confident", "certain", "definitely", "clearly",
            "strong evidence", "conclusive", "confirmed"
        ]
        
        uncertainty_indicators = [
            "low confidence", "uncertain", "unclear", "possibly", "might be", 
            "could be", "not sure", "insufficient evidence", "ambiguous"
        ]
        
        # Count indicators
        confidence_count = sum(1 for indicator in confidence_indicators if indicator.lower() in response_content.lower())
        uncertainty_count = sum(1 for indicator in uncertainty_indicators if indicator.lower() in response_content.lower())
        
        # Calculate base confidence
        if confidence_count + uncertainty_count == 0:
            # No explicit indicators, default to medium confidence
            return 0.5
        
        # Calculate weighted confidence
        return min(1.0, max(0.0, 0.5 + (confidence_count - uncertainty_count) * 0.1))
    
    def query(self, messages: List[Dict[str, str]], 
              system_prompt: Optional[str] = None) -> Dict[str, Union[str, float]]:
        """Query LLM with fallback mechanism.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            system_prompt: Optional system prompt to prepend
            
        Returns:
            Dictionary with 'content' (response text) and 'confidence' (estimated confidence)
        """
        # Add system prompt if provided
        if system_prompt:
            messages = [{'role': 'system', 'content': system_prompt}] + messages
        
        # Try primary model (Ollama)
        for attempt in range(self.max_retries):
            try:
                self.logger.info(f"Querying primary model {self.primary_model} (attempt {attempt+1}/{self.max_retries})")
                response = ollama_chat(self.primary_model, messages=messages)
                content = response.message.content
                
                # Estimate confidence
                confidence = self._extract_confidence(content)
                
                # If confidence is high enough, return the result
                if confidence >= self.confidence_threshold:
                    return {
                        'content': content,
                        'confidence': confidence,
                        'model': self.primary_model,
                        'fallback_used': False
                    }
                else:
                    self.logger.info(f"Primary model confidence ({confidence}) below threshold ({self.confidence_threshold})")
            
            except Exception as e:
                self.logger.warning(f"Error with primary model: {str(e)}")
        
        # Fall back to OpenAI if available
        if self.openai_enabled:
            try:
                self.logger.info(f"Falling back to OpenAI model {self.fallback_model}")
                
                # Configure OpenAI client
                client = openai.OpenAI(api_key=self.openai_api_key)
                
                # Make OpenAI API call
                response = client.chat.completions.create(
                    model=self.fallback_model,
                    messages=[{"role": m["role"], "content": m["content"]} for m in messages],
                    temperature=0.2,  # Lower temperature for more deterministic responses
                )
                
                content = response.choices[0].message.content
                
                # OpenAI responses are generally high confidence
                return {
                    'content': content,
                    'confidence': 0.9,  # Assume high confidence from OpenAI
                    'model': self.fallback_model,
                    'fallback_used': True
                }
                
            except Exception as e:
                self.logger.error(f"Error with fallback model: {str(e)}")
        
        # If we get here, both primary and fallback failed or fallback not available
        self.logger.error("All LLM attempts failed")
        return {
            'content': "Unable to generate a reliable analysis. Please try again or review manually.",
            'confidence': 0.0,
            'model': None,
            'fallback_used': None
        }