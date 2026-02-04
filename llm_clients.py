"""
LLM Clients: Real implementations for Analyst Engine and Agent Brain
=====================================================================

This module provides real LLM implementations using Google's Gemini API.
Falls back to mock implementations if no API key is available.

Usage:
    from llm_clients import get_analyst_llm, get_agent_llm
    
    analyst_llm = get_analyst_llm()  # For scam detection
    agent_llm = get_agent_llm()      # For persona responses
"""

from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

# Try to import google-generativeai, handle if not installed
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("[LLMClients] google-generativeai not installed. Run: pip install google-generativeai")

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[LLMClients] python-dotenv not installed. Environment variables must be set manually.")


# =============================================================================
# SECTION 1: ABSTRACT INTERFACES
# =============================================================================

class AnalystLLMInterface(ABC):
    """Interface for Analyst Engine LLM (scam detection)."""
    
    @abstractmethod
    def call_llm(self, prompt: str) -> str:
        """Call LLM with a prompt and return response string."""
        pass


class AgentLLMInterface(ABC):
    """Interface for Agent Brain LLM (persona responses)."""
    
    @abstractmethod
    def generate(self, system_prompt: str, user_message: str, history: List[Dict[str, str]]) -> str:
        """Generate a response using the LLM."""
        pass


# =============================================================================
# SECTION 2: GEMINI IMPLEMENTATIONS
# =============================================================================

class GeminiAnalystLLM(AnalystLLMInterface):
    """
    Real Gemini implementation for the Analyst Engine.
    
    Uses Gemini 2.5 Flash for fast scam detection with fallback to 2.5 Pro.
    """
    
    PRIMARY_MODEL = "gemini-2.5-flash"
    FALLBACK_MODEL = "gemini-2.5-pro"
    
    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        """
        Initialize Gemini client for analyst.
        
        Args:
            api_key: Gemini API key. Falls back to GEMINI_API_KEY env var.
            model_name: Model to use (default: gemini-2.5-flash).
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or self.PRIMARY_MODEL
        self.model = None
        
        if not GEMINI_AVAILABLE:
            raise RuntimeError("google-generativeai package not installed")
        
        if not self.api_key or self.api_key == "your_gemini_api_key_here":
            raise ValueError("Valid GEMINI_API_KEY required. Set in .env file or pass directly.")
        
        # Configure and initialize with fallback support
        genai.configure(api_key=self.api_key)
        
        # Try primary model, fallback if needed
        try:
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config={
                    "temperature": 0.3,  # Low temp for consistent analysis
                    "top_p": 0.8,
                    "max_output_tokens": 500,
                }
            )
            # Test the model with a simple call
            print(f"[GeminiAnalystLLM] Initialized with model: {self.model_name}")
        except Exception as e:
            print(f"[GeminiAnalystLLM] Primary model {self.model_name} failed: {e}")
            print(f"[GeminiAnalystLLM] Trying fallback model: {self.FALLBACK_MODEL}")
            self.model_name = self.FALLBACK_MODEL
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config={
                    "temperature": 0.3,
                    "top_p": 0.8,
                    "max_output_tokens": 500,
                }
            )
            print(f"[GeminiAnalystLLM] Initialized with fallback model: {self.model_name}")
    
    def call_llm(self, prompt: str) -> str:
        """
        Call Gemini API for scam detection.
        
        Args:
            prompt: The complete prompt for scam analysis.
            
        Returns:
            JSON string with detection results.
        """
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"[GeminiAnalystLLM] API Error: {e}")
            # Return safe default on error
            return json.dumps({
                "is_scam": True,
                "risk_category": "unknown",
                "reason": f"API error - defaulting to safe engagement: {str(e)}"
            })


class GeminiAgentLLM(AgentLLMInterface):
    """
    Real Gemini implementation for the Agent Brain.
    
    Uses Gemini 2.5 Flash for persona response generation with fallback to 2.5 Pro.
    """
    
    PRIMARY_MODEL = "gemini-2.5-flash"
    FALLBACK_MODEL = "gemini-2.5-pro"
    
    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        """
        Initialize Gemini client for agent.
        
        Args:
            api_key: Gemini API key. Falls back to GEMINI_API_KEY env var.
            model_name: Model to use (default: gemini-2.5-flash).
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or self.PRIMARY_MODEL
        self.model = None
        
        if not GEMINI_AVAILABLE:
            raise RuntimeError("google-generativeai package not installed")
        
        if not self.api_key or self.api_key == "your_gemini_api_key_here":
            raise ValueError("Valid GEMINI_API_KEY required. Set in .env file or pass directly.")
        
        # Configure and initialize with fallback support
        genai.configure(api_key=self.api_key)
        
        # Try primary model, fallback if needed
        try:
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config={
                    "temperature": 0.7,  # Higher temp for creative persona responses
                    "top_p": 0.9,
                    "max_output_tokens": 300,
                }
            )
            print(f"[GeminiAgentLLM] Initialized with model: {self.model_name}")
        except Exception as e:
            print(f"[GeminiAgentLLM] Primary model {self.model_name} failed: {e}")
            print(f"[GeminiAgentLLM] Trying fallback model: {self.FALLBACK_MODEL}")
            self.model_name = self.FALLBACK_MODEL
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config={
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "max_output_tokens": 300,
                }
            )
            print(f"[GeminiAgentLLM] Initialized with fallback model: {self.model_name}")
    
    def generate(self, system_prompt: str, user_message: str, history: List[Dict[str, str]]) -> str:
        """
        Generate a persona response.
        
        Args:
            system_prompt: The persona system prompt.
            user_message: Current message from scammer.
            history: Previous conversation messages.
            
        Returns:
            Generated response as Ramesh Gupta.
        """
        try:
            # Build the full prompt
            full_prompt = f"""{system_prompt}

CONVERSATION HISTORY:
"""
            for msg in history[-6:]:
                role = "SCAMMER" if msg.get('role') == 'user' else "YOU (Ramesh)"
                full_prompt += f"{role}: {msg.get('text', '')}\n"
            
            full_prompt += f"""
SCAMMER: {user_message}

YOUR RESPONSE (as Ramesh Gupta, confused elderly man):"""
            
            response = self.model.generate_content(full_prompt)
            return response.text
            
        except Exception as e:
            print(f"[GeminiAgentLLM] API Error: {e}")
            return "sir?? hello?? my phone suddenly hung.. what did you say??"


# =============================================================================
# SECTION 3: MOCK IMPLEMENTATIONS (Fallback)
# =============================================================================

class MockAnalystLLM(AnalystLLMInterface):
    """Mock LLM for testing without API key."""
    
    SCAM_INDICATORS = [
        'block', 'suspend', 'verify', 'urgent', 'otp', 'upi', 'bank',
        'account', 'password', 'pin', 'kyc', 'lottery', 'winner',
        'prize', 'claim', 'arrested', 'police', 'court', 'blocked'
    ]
    
    def call_llm(self, prompt: str) -> str:
        """Simulate LLM response based on keyword detection."""
        prompt_lower = prompt.lower()
        indicator_count = sum(1 for ind in self.SCAM_INDICATORS if ind in prompt_lower)
        
        if indicator_count >= 2:
            return json.dumps({
                "is_scam": True,
                "risk_category": "financial",
                "reason": f"[MOCK] Detected {indicator_count} scam indicators"
            })
        elif indicator_count == 1:
            return json.dumps({
                "is_scam": True,
                "risk_category": "urgent",
                "reason": "[MOCK] Single suspicious indicator detected"
            })
        else:
            return json.dumps({
                "is_scam": False,
                "risk_category": "safe",
                "reason": "[MOCK] No scam indicators detected"
            })


class MockAgentLLM(AgentLLMInterface):
    """Mock LLM for testing persona responses without API key."""
    
    RESPONSES = [
        "sir ji what happened?? please tell me I am confused only..",
        "arey sir I am trying but not working.. my phone is old samsung..",
        "ok sir ok sir.. let me try again.. please hold..",
        "sir but this is showing error only.. network problem hai..",
        "hello?? sir you there?? my screen flickered..",
    ]
    
    def generate(self, system_prompt: str, user_message: str, history: List[Dict[str, str]]) -> str:
        """Generate mock response."""
        import random
        return random.choice(self.RESPONSES)


# =============================================================================
# SECTION 4: FACTORY FUNCTIONS
# =============================================================================

def get_analyst_llm(api_key: Optional[str] = None, force_mock: bool = False) -> AnalystLLMInterface:
    """
    Get an Analyst LLM instance.
    
    Returns GeminiAnalystLLM if API key available, else MockAnalystLLM.
    
    Args:
        api_key: Optional API key override.
        force_mock: If True, always return mock (for testing).
        
    Returns:
        LLM instance implementing AnalystLLMInterface.
    """
    if force_mock:
        print("[LLMClients] Using MockAnalystLLM (forced)")
        return MockAnalystLLM()
    
    key = api_key or os.getenv("GEMINI_API_KEY")
    
    if key and key != "your_gemini_api_key_here" and GEMINI_AVAILABLE:
        try:
            return GeminiAnalystLLM(api_key=key)
        except Exception as e:
            print(f"[LLMClients] Failed to init Gemini: {e}")
            print("[LLMClients] Falling back to MockAnalystLLM")
            return MockAnalystLLM()
    else:
        print("[LLMClients] No API key found. Using MockAnalystLLM")
        return MockAnalystLLM()


def get_agent_llm(api_key: Optional[str] = None, force_mock: bool = False) -> AgentLLMInterface:
    """
    Get an Agent LLM instance.
    
    Returns GeminiAgentLLM if API key available, else MockAgentLLM.
    
    Args:
        api_key: Optional API key override.
        force_mock: If True, always return mock (for testing).
        
    Returns:
        LLM instance implementing AgentLLMInterface.
    """
    if force_mock:
        print("[LLMClients] Using MockAgentLLM (forced)")
        return MockAgentLLM()
    
    key = api_key or os.getenv("GEMINI_API_KEY")
    
    if key and key != "your_gemini_api_key_here" and GEMINI_AVAILABLE:
        try:
            return GeminiAgentLLM(api_key=key)
        except Exception as e:
            print(f"[LLMClients] Failed to init Gemini: {e}")
            print("[LLMClients] Falling back to MockAgentLLM")
            return MockAgentLLM()
    else:
        print("[LLMClients] No API key found. Using MockAgentLLM")
        return MockAgentLLM()


# =============================================================================
# SECTION 5: QUICK TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("LLM Clients Test")
    print("=" * 60)
    
    # Test Analyst LLM
    print("\n--- Testing Analyst LLM ---")
    analyst = get_analyst_llm()
    result = analyst.call_llm("Your account is blocked! Send OTP immediately!")
    print(f"Response: {result}")
    
    # Test Agent LLM
    print("\n--- Testing Agent LLM ---")
    agent = get_agent_llm()
    response = agent.generate(
        system_prompt="You are Ramesh Gupta, a confused 67-year-old.",
        user_message="Sir your account will be blocked!",
        history=[]
    )
    print(f"Response: {response}")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)
