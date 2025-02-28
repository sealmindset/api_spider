from ollama import chat

class LLMAnalyzer:
    def __init__(self, model_name='llama3.3'):
        self.model_name = model_name
        self.messages = []

    def analyze(self, query, context=None):
        """Analyze a security-related query with context and maintain chat history."""
        if context:
            # Add context to the query
            query = f"Context: {context}\n\nQuery: {query}"

        # Add the user query to messages
        self.messages.append({
            'role': 'user',
            'content': query
        })

        # Get response from the model
        response = chat(
            self.model_name,
            messages=self.messages
        )

        # Add the assistant's response to messages
        self.messages.append({
            'role': 'assistant',
            'content': response.message.content
        })

        return response.message.content

    def clear_history(self):
        """Clear the chat history."""
        self.messages = []

    def get_history(self):
        """Get the current chat history."""
        return self.messages