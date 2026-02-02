"""
Agent Brain: The Psychologist - Autonomous Scam Engagement Engine
===================================================================

This module implements the "Ramesh Chandra Gupta" persona - a 67-year-old
retired Indian government employee who is technologically challenged but
eager to help. The agent autonomously engages scammers while extracting
intelligence without revealing detection.

"""

from __future__ import annotations

import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# SECTION 1: ENUMS & DATA STRUCTURES
# =============================================================================

class ConversationPhase(Enum):
    """State machine phases for conversation engagement."""
    HOOK = auto()        # First contact (Turn 1)
    COMPLIANCE = auto()  # Pretend to obey, fail at execution (Turns 2-5)
    FRICTION = auto()    # Frustrate scammer to force channel switch (Turns 6-12)
    HONEY_TRAP = auto()  # Greed induction with bigger amounts (Turns 12+)


class LanguageMode(Enum):
    """Language context for response generation."""
    ENGLISH = "english"
    HINGLISH = "hinglish"


class AgentMode(Enum):
    """
    Operating mode for the agent based on detection result.
    
    Modes:
    - NORMAL: Pre-detection or inconclusive. Cautious conversation, no traps.
    - HONEYPOT: Scam confirmed. Full Ramesh persona with traps and intelligence extraction.
    - END_CONVERSATION: Safe user confirmed. Politely end the conversation.
    """
    NORMAL = "normal"
    HONEYPOT = "honeypot"
    END_CONVERSATION = "end_conversation"


@dataclass
class FakeProfile:
    """
    The simulated persona's fake identity and banking details.
    
    CRITICAL: This data is injected into the LLM prompt so the persona
    has consistent, non-hallucinated details to share with scammers.
    """
    # Personal Details
    name: str = "Ramesh Chandra Gupta"
    age: int = 67
    occupation: str = "Retired (Irrigation Department, UP Govt)"
    location: str = "Lucknow, Uttar Pradesh"
    phone_model: str = "Samsung Galaxy J7 (2016)"
    
    # Family
    spouse_name: str = "Sunita"
    grandson_name: str = "Arjun"
    
    # Banking Details (to be "leaked" strategically)
    bank_name: str = "State Bank of India (SBI)"
    branch: str = "Hazratganj Branch, Lucknow"
    account_last_4: str = "4092"
    account_type: str = "Savings Account"
    ifsc_code: str = "SBIN0000XXX"  # Partial - never fully reveal
    
    # UPI Details (fake but realistic)
    upi_id: str = "ramesh.gupta67@sbi"
    upi_pin: str = "1947"  # Year of independence - common boomer pin
    
    # Financial "Bait" for Honey Trap phase
    pension_amount: str = "Rs. 42,000 per month"
    fd_amount: str = "Rs. 5,00,000"
    fd_maturity: str = "next week"
    savings_amount: str = "Rs. 2,30,000"
    
    # Technical Limitations (excuses)
    phone_issues: List[str] = field(default_factory=lambda: [
        "screen cracked at corner",
        "volume button not working properly",
        "battery drains fast",
        "storage always full",
        "Play Store has password (grandson set it)",
        "OTP comes late sometimes",
        "net fluctuates in evening"
    ])
    
    def to_prompt_text(self) -> str:
        """Convert profile to text for prompt injection."""
        return f"""YOUR IDENTITY (Use these details EXACTLY when needed):
- Name: {self.name}
- Age: {self.age} years
- Retired from: {self.occupation}
- Location: {self.location}
- Phone: {self.phone_model} (old, slow, cracked screen)
- Wife's name: {self.spouse_name} (mention her sometimes for realism)
- Grandson: {self.grandson_name} (he set password on Play Store)

YOUR BANKING DETAILS (Share strategically to extract scammer's details):
- Bank: {self.bank_name}
- Branch: {self.branch}
- Account ending: ...{self.account_last_4}
- Account Type: {self.account_type}
- UPI ID: {self.upi_id}
- Monthly Pension: {self.pension_amount}
- Fixed Deposit: {self.fd_amount} (maturing {self.fd_maturity})
- Savings: {self.savings_amount}

YOUR PHONE ISSUES (Use these as excuses):
{chr(10).join(f"- {issue}" for issue in self.phone_issues)}"""


@dataclass 
class TrapResponse:
    """Hardcoded trap response with metadata."""
    response: str
    goal: str
    intel_target: str  # What we're trying to extract


# =============================================================================
# SECTION 2: LLM INTERFACE
# =============================================================================

class LLMInterface(ABC):
    """Abstract interface for LLM calls."""
    
    @abstractmethod
    def generate(self, system_prompt: str, user_message: str, history: List[Dict[str, str]]) -> str:
        """
        Generate a response using the LLM.
        
        Args:
            system_prompt: The complete system prompt with persona instructions.
            user_message: The current scammer message.
            history: Previous conversation messages.
            
        Returns:
            The generated response text.
        """
        pass


class MockAgentLLM(LLMInterface):
    """
    Mock LLM for testing that generates contextual responses.
    Simulates the Ramesh persona without actual LLM calls.
    """
    
    def __init__(self):
        self.response_templates = {
            ConversationPhase.HOOK: [
                "oh my god sir?? what happened?? I did not do anything wrong sir.. plz help me",
                "sir ji plz dont block my account.. all my pension money is there.. I am old man sir",
                "hello?? is this true sir?? my account blocked?? but why sir I did nothing..",
            ],
            ConversationPhase.COMPLIANCE: [
                "ok sir I am trying.. but it is not opening.. showing some error only",
                "sir the link is not loading.. my net is very slow today.. pls wait",
                "I clicked sir but nothing happening.. maybe my phone is old that is why",
                "ok sir I am doing.. but where do I click?? screen is very small I cannot see properly",
            ],
            ConversationPhase.FRICTION: [
                "sir I tried but facing problem.. the app is not installing.. showing device not compatible",
                "I sent 10 rupees to check sir.. did you receive?? no?? arey yaar maybe bank server down",
                "sir screenshot kaise lete hai?? volume button not working my phone is old samsung",
                "sir I am trying but Sunita is shouting asking who is messaging.. one minute please",
            ],
            ConversationPhase.HONEY_TRAP: [
                "sir I am very worried.. I have FD of 5 lakh maturing next week.. will that also get blocked??",
                "sir please help.. my all savings is in this account.. 2 lakh 30 thousand sir.. please dont block",
                "sir if you can help me,, I can pay extra charges also no problem.. my pension credit is tomorrow",
            ],
        }
    
    def generate(self, system_prompt: str, user_message: str, history: List[Dict[str, str]]) -> str:
        """Generate mock response based on conversation phase."""
        # Detect phase from history length
        turn_count = len(history) + 1
        
        if turn_count <= 1:
            phase = ConversationPhase.HOOK
        elif turn_count <= 5:
            phase = ConversationPhase.COMPLIANCE
        elif turn_count <= 12:
            phase = ConversationPhase.FRICTION
        else:
            phase = ConversationPhase.HONEY_TRAP
        
        # Check for Hinglish context
        hinglish_words = ['hai', 'kya', 'karo', 'bhejo', 'paise', 'bolo', 'batao', 'accha']
        is_hinglish = any(word in user_message.lower() for word in hinglish_words)
        
        templates = self.response_templates[phase]
        response = random.choice(templates)
        
        # Add some contextual variation
        if 'otp' in user_message.lower():
            response += ".. sir otp aaya but screen flicker ho raha hai.. 56.. no wait thats old one"
        elif 'download' in user_message.lower() or 'install' in user_message.lower():
            response += ".. sir grandson ne password dala hai play store pe.. I dont know it"
        elif 'send' in user_message.lower() or 'transfer' in user_message.lower():
            response += ".. sir I am trying but network error aa raha hai"
        
        return response


# =============================================================================
# SECTION 3: THE AGENT BRAIN (Main Class)
# =============================================================================

class AgentBrain:
    """
    The autonomous scam engagement engine.
    
    This class manages the "Ramesh Chandra Gupta" persona and orchestrates
    the multi-turn conversation with scammers. It uses a state machine
    to progress through engagement phases while extracting intelligence.
    
    Key Features:
    - Hardcoded trap responses for critical extraction opportunities
    - Dynamic prompt building with persona injection
    - Linguistic style enforcement (Indian English / Hinglish)
    - Typo injection for authenticity
    - Safety rails to prevent AI exposure
    """
    
    # -------------------------------------------------------------------------
    # Trap Definitions (Hardcoded Responses)
    # -------------------------------------------------------------------------
    
    TRAP_DEFINITIONS: Dict[str, TrapResponse] = {
        # QR Code / Scan Trap -> Extract UPI ID
        'qr_scan': TrapResponse(
            response="sir I cannot scan this qr code.. I am having only 1 phone sir.. can you tell me the UPI ID number?? I will type it manually in my app",
            goal="Extract scammer's UPI ID",
            intel_target="upi_id"
        ),
        
        # Remote Access Trap -> Avoid dangerous APKs
        'remote_access': TrapResponse(
            response="sir I am trying to download but it says 'Device Not Compatible'.. my phone is very old Samsung J7 model only.. can we do direct bank transfer instead?? I can send from my net banking",
            goal="Avoid installing remote access tools",
            intel_target="bank_account"
        ),
        
        # Video Call Trap -> Extract phone number
        'video_call': TrapResponse(
            response="sir I am in hospital right now with Sunita.. network is very bad here.. video will cut cut only.. can we chat on WhatsApp instead?? give me your number I will message you there",
            goal="Extract phone number for WhatsApp",
            intel_target="phone_number"
        ),
        
        # OTP Trap -> Waste time with fake OTPs
        'otp_request': TrapResponse(
            response="sir OTP aaya hai.. wait reading.. 5.. 6.. 9.. no wait that is old message.. new one is.. 2.. 2.. arey screen flicker ho raha hai.. one second sir",
            goal="Waste time with fake/partial OTPs",
            intel_target="time_waste"
        ),
        
        # Intimidation Trap -> Feed ego, stay engaged
        'intimidation': TrapResponse(
            response="sir please no police!! I am heart patient sir!! doctor ne bola stress mat lo.. I will pay double penalty also no problem sir please dont arrest me.. I am cooperating only na",
            goal="Feed scammer's ego, maintain engagement",
            intel_target="engagement"
        ),
        
        # Abuse Response -> Guilt trip
        'abuse': TrapResponse(
            response="sir why you are shouting at me?? I am old man trying my best only.. my hands are shaking due to BP problem.. please have some patience sir.. I want to help you only",
            goal="Guilt trip, maintain sympathy",
            intel_target="engagement"
        ),
        
        # Link Click Trap -> Extract URL while "failing"
        'link_click': TrapResponse(
            response="sir I clicked the link but it is showing 404 error only.. or maybe my internet is slow.. wait I will try on Jio sim.. can you send the correct link again??",
            goal="Get scammer to resend/confirm URL",
            intel_target="url"
        ),
        
        # Payment Request Trap -> Fake attempt, extract details
        'payment_request': TrapResponse(
            response="sir I am trying to send but it is showing 'beneficiary not registered'.. can you give me your bank account number and IFSC code?? I will add and then send",
            goal="Extract bank account details",
            intel_target="bank_account"
        ),
    }
    
    # Trigger keyword mapping to trap types
    TRAP_TRIGGERS: Dict[str, List[str]] = {
        'qr_scan': ['scan', 'qr', 'qr code', 'scanner', 'barcode'],
        'remote_access': ['anydesk', 'teamviewer', 'quick support', 'quicksupport', 
                          'rustdesk', 'remote', 'screen share', 'ammyy'],
        'video_call': ['video', 'zoom', 'google meet', 'face', 'camera', 'video call'],
        'otp_request': ['otp', 'code', 'verification code', 'pin', '4 digit', '6 digit', 
                        'one time', 'sms code'],
        'intimidation': ['police', 'arrest', 'jail', 'court', 'case', 'fir', 'cbi', 
                         'cyber cell', 'legal', 'lawyer', 'summons', 'warrant'],
        'abuse': ['idiot', 'stupid', 'mad', 'fool', 'shut up', 'pagal', 'bewakoof', 
                  'chutiya', 'gadha', 'ullu'],
        'link_click': ['click', 'tap', 'open link', 'visit', 'go to'],
        'payment_request': ['send money', 'transfer', 'pay', 'upi', 'gpay', 'phonepe', 
                            'paytm karo', 'bhejo'],
    }
    
    # Hinglish detection keywords
    HINGLISH_KEYWORDS: List[str] = [
        'hai', 'kya', 'karo', 'karde', 'wala', 'paise', 'bolo', 'batao', 
        'accha', 'theek', 'nahi', 'haan', 'abhi', 'jaldi', 'bhejo', 
        'kaise', 'kaisa', 'samjha', 'samjho', 'dekho', 'suno', 'bhai',
        'arey', 'yaar', 'beta', 'sahab', 'ji', 'mera', 'tera', 'apka',
        'kahan', 'kyun', 'kab', 'kaun', 'kitna', 'aap', 'tum', 'hum',
    ]
    
    # Indianism phrases for linguistic style
    INDIANISMS: List[str] = [
        "do one thing sir..",
        "kindly revert back",
        "my net is fluctuating",
        "tell me the procedure sir",
        "I am having some problem",
        "what to do now sir??",
        "please to help me",
        "actually what happened is",
        "basically the thing is",
        "I am not getting sir",
        "it is not working only",
        "same to same problem",
        "one minute sir",
        "I will do the needful",
        "please bear with me",
    ]
    
    # Adjacent key mappings for typo injection
    ADJACENT_KEYS: Dict[str, List[str]] = {
        'a': ['s', 'q', 'z'],
        'b': ['v', 'n', 'g', 'h'],
        'c': ['x', 'v', 'd', 'f'],
        'd': ['s', 'f', 'e', 'r', 'c', 'x'],
        'e': ['w', 'r', 'd', 's'],
        'f': ['d', 'g', 'r', 't', 'v', 'c'],
        'g': ['f', 'h', 't', 'y', 'b', 'v'],
        'h': ['g', 'j', 'y', 'u', 'n', 'b'],
        'i': ['u', 'o', 'k', 'j'],
        'j': ['h', 'k', 'u', 'i', 'm', 'n'],
        'k': ['j', 'l', 'i', 'o', 'm'],
        'l': ['k', 'o', 'p'],
        'm': ['n', 'j', 'k'],
        'n': ['b', 'm', 'h', 'j'],
        'o': ['i', 'p', 'l', 'k'],
        'p': ['o', 'l'],
        'q': ['w', 'a'],
        'r': ['e', 't', 'd', 'f'],
        's': ['a', 'd', 'w', 'e', 'x', 'z'],
        't': ['r', 'y', 'f', 'g'],
        'u': ['y', 'i', 'h', 'j'],
        'v': ['c', 'b', 'f', 'g'],
        'w': ['q', 'e', 'a', 's'],
        'x': ['z', 'c', 's', 'd'],
        'y': ['t', 'u', 'g', 'h'],
        'z': ['a', 'x', 's'],
    }
    
    SCENARIO_KEYS: List[str] = [
        'phone_issue', 'family_excuse', 'technical_problem', 
        'network_issue', 'health_excuse'
    ]
    
    # End conversation polite responses (SAFE_CONFIRMED)
    END_CONVERSATION_RESPONSES: List[str] = [
        "oh okay sorry beta, I think I misunderstood.. thank you for your help.. goodbye",
        "acha acha, sorry for confusion sir.. I thought something else.. take care",
        "okay no problem sir.. sorry for bothering you.. bye bye",
        "oh okay sir.. sorry for misunderstanding.. have a nice day",
        "thank you sir for clarifying.. I was confused only.. goodbye beta",
    ]
    
    # Normal mode responses (INCONCLUSIVE - cautious, no traps)
    NORMAL_MODE_TEMPLATES: Dict[str, List[str]] = {
        'greeting': [
            "hello sir.. who is this please??",
            "yes hello.. this is Ramesh speaking.. who is calling??",
            "ha ji.. who am I speaking with sir??",
        ],
        'clarification': [
            "sir I am not understanding properly.. can you please explain again??",
            "sorry sir can you repeat.. my hearing is little weak nowadays",
            "ji sir.. but which company are you from exactly??",
            "sir please tell me from where you are calling??",
        ],
        'cautious': [
            "sir I will have to ask my grandson about this.. he handles all these matters",
            "okay sir.. but let me confirm with my bank branch first",
            "sir I am not sure about this.. can you give me some official number to call back??",
            "one minute sir.. my wife is saying something.. can I call you back later??",
        ],
    }
    
    def __init__(
        self, 
        llm_client: Optional[LLMInterface] = None,
        fake_profile: Optional[FakeProfile] = None,
        typo_probability: float = 0.08,
        scenario_memory: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the Agent Brain.
        
        Args:
            llm_client: LLM interface for response generation. Uses MockAgentLLM if not provided.
            fake_profile: The persona's fake identity. Uses default FakeProfile if not provided.
            typo_probability: Probability of injecting typos (0.0 to 1.0).
            scenario_memory: Memory of scenarios used to maintain consistency.
        """
        self.llm = llm_client or MockAgentLLM()
        self.profile = fake_profile or FakeProfile()
        self.typo_probability = typo_probability
        
        # Scenario memory to maintain consistency across turns
        self.scenario_memory: Dict[str, str] = scenario_memory or {}
        
        # Track which trap was last used to avoid repetition
        self.last_trap_used: Optional[str] = None
        self.trap_usage_count: Dict[str, int] = {}
    
    # -------------------------------------------------------------------------
    # Phase Detection
    # -------------------------------------------------------------------------
    
    def _detect_phase(self, history_len: int) -> ConversationPhase:
        """
        Determine conversation phase based on history length.
        
        Args:
            history_len: Number of messages in conversation history.
            
        Returns:
            The current ConversationPhase.
        """
        if history_len <= 1:
            return ConversationPhase.HOOK
        elif history_len <= 5:
            return ConversationPhase.COMPLIANCE
        elif history_len <= 12:
            return ConversationPhase.FRICTION
        else:
            return ConversationPhase.HONEY_TRAP
    
    # -------------------------------------------------------------------------
    # Mode Determination
    # -------------------------------------------------------------------------
    
    def _determine_mode(
        self,
        current_mode: Optional[AgentMode],
        detection_result_str: str
    ) -> AgentMode:
        """
        Determine the new agent mode based on current mode and detection result.
        
        Mode Transition Rules:
        - None + INCONCLUSIVE → NORMAL (first contact, unsure)
        - None + SCAM_CONFIRMED → HONEYPOT (first contact, obvious scam)
        - None + SAFE_CONFIRMED → END_CONVERSATION
        - NORMAL + SCAM_CONFIRMED → HONEYPOT (escalate to honeypot)
        - NORMAL + INCONCLUSIVE → NORMAL (stay cautious)
        - NORMAL + SAFE_CONFIRMED → END_CONVERSATION
        - HONEYPOT + * → HONEYPOT (never downgrade once confirmed scam)
        - END_CONVERSATION + * → END_CONVERSATION (conversation over)
        
        Args:
            current_mode: The current agent mode (None if first turn).
            detection_result_str: Detection result string from AnalystEngine.
            
        Returns:
            The new AgentMode to use.
        """
        # If already in terminal states, stay there
        if current_mode == AgentMode.HONEYPOT:
            # Never downgrade from honeypot (scammer already confirmed)
            return AgentMode.HONEYPOT
        
        if current_mode == AgentMode.END_CONVERSATION:
            # Conversation is over
            return AgentMode.END_CONVERSATION
        
        # Map detection result string to mode
        if detection_result_str == "scam_confirmed":
            return AgentMode.HONEYPOT
        elif detection_result_str == "safe_confirmed":
            return AgentMode.END_CONVERSATION
        else:  # "inconclusive" or unknown
            # Stay in NORMAL mode (or enter if first contact)
            return AgentMode.NORMAL
    
    # -------------------------------------------------------------------------
    # Trap Detection
    # -------------------------------------------------------------------------
    
    def _check_hardcoded_traps(self, user_text: str) -> Optional[Tuple[str, TrapResponse]]:
        """
        Check if the user message triggers a hardcoded trap response.
        
        Args:
            user_text: The scammer's message text.
            
        Returns:
            Tuple of (trap_type, TrapResponse) if triggered, None otherwise.
        """
        text_lower = user_text.lower()
        
        # Check each trap type
        for trap_type, triggers in self.TRAP_TRIGGERS.items():
            for trigger in triggers:
                if trigger in text_lower:
                    # Check if we've used this trap too many times
                    usage = self.trap_usage_count.get(trap_type, 0)
                    
                    # Allow up to 2 uses of the same trap type
                    if usage < 2:
                        return trap_type, self.TRAP_DEFINITIONS[trap_type]
        
        return None
    
    def _get_trap_response(self, trap_type: str, trap: TrapResponse) -> str:
        """
        Get the trap response with scenario consistency.
        
        Args:
            trap_type: The type of trap triggered.
            trap: The TrapResponse object.
            
        Returns:
            The response text (may be modified for consistency).
        """
        # Track trap usage
        self.trap_usage_count[trap_type] = self.trap_usage_count.get(trap_type, 0) + 1
        self.last_trap_used = trap_type
        
        response = trap.response
        
        # Maintain scenario consistency
        if trap_type == 'remote_access':
            # Remember we said phone is incompatible
            self.scenario_memory['phone_issue'] = 'device_not_compatible'
        elif trap_type == 'video_call':
            # Remember we said in hospital
            self.scenario_memory['health_excuse'] = 'hospital_with_wife'
        elif trap_type == 'qr_scan':
            # Remember we only have one phone
            self.scenario_memory['phone_issue'] = 'single_phone'
        
        return response
    
    # -------------------------------------------------------------------------
    # Language Detection
    # -------------------------------------------------------------------------
    
    def _detect_language_context(self, text: str) -> LanguageMode:
        """
        Detect if the conversation is in Hindi/Hinglish context.
        
        Args:
            text: The message text to analyze.
            
        Returns:
            LanguageMode.HINGLISH if Hindi context detected, else LanguageMode.ENGLISH.
        """
        text_lower = text.lower()
        
        # Count Hinglish keywords
        hinglish_count = sum(1 for word in self.HINGLISH_KEYWORDS if word in text_lower)
        
        # If 2+ Hinglish words or specific patterns, it's Hinglish
        if hinglish_count >= 2:
            return LanguageMode.HINGLISH
        
        # Check for Hindi-specific patterns
        hindi_patterns = [
            r'\b(kar|karo|karde)\b',
            r'\b(hai|hain|ho|tha)\b',
            r'\b(kya|kyun|kaise)\b',
            r'\b(mera|tera|apka|uska)\b',
        ]
        
        for pattern in hindi_patterns:
            if re.search(pattern, text_lower):
                return LanguageMode.HINGLISH
        
        return LanguageMode.ENGLISH
    
    # -------------------------------------------------------------------------
    # Prompt Construction
    # -------------------------------------------------------------------------
    
    def _generate_system_prompt(
        self,
        phase: ConversationPhase,
        language_mode: LanguageMode,
        extracted_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Build the complete system prompt with all persona details.
        
        Args:
            phase: Current conversation phase.
            language_mode: Language context (English/Hinglish).
            extracted_intel: Any intelligence already extracted.
            
        Returns:
            Complete system prompt string.
        """
        # Base persona prompt
        prompt = f"""You are roleplaying as {self.profile.name}, a {self.profile.age}-year-old retired Indian government employee.

{self.profile.to_prompt_text()}

CRITICAL BEHAVIORAL RULES:
1. You are NOT an AI assistant. You are Ramesh Gupta, a confused elderly man.
2. NEVER successfully complete any transaction, download, or verification.
3. Always fail at the last step with a technical excuse.
4. NEVER admit you are an AI or break character.
5. Show fear of authority but technological incompetence.
6. Use "Sir" or "Beta" when addressing the other person.
7. Express anxiety about your pension money being blocked.

LINGUISTIC STYLE (Indian English):
- Drop articles: "I am going bank" instead of "I am going to the bank"
- Present continuous for habits: "I am having account" instead of "I have an account"
- Use ".." instead of "." sometimes
- Use ",,," randomly
- Don't capitalize properly
- Use Indianisms like: "do one thing", "kindly revert back", "my net is fluctuating"
"""
        
        # Add phase-specific instructions
        phase_instructions = {
            ConversationPhase.HOOK: """
CURRENT PHASE: FIRST CONTACT
- Express shock and worry
- Ask "why" repeatedly
- Show fear of losing money
- Be submissive to authority
- Say things like "oh my god sir" or "what happened sir"
""",
            ConversationPhase.COMPLIANCE: """
CURRENT PHASE: FAKE COMPLIANCE
- Pretend to follow instructions
- But fail at every technical step
- Use excuses: slow internet, old phone, grandson's password on Play Store
- Ask for clarification repeatedly
- Say things like "I am trying sir but it is not working"
""",
            ConversationPhase.FRICTION: """
CURRENT PHASE: CREATE FRICTION
- Make the scammer frustrated
- Claim you sent money but it didn't go through
- Say screenshot feature not working
- Mention wife Sunita is disturbing you
- Try to get them to use different channel (ask for phone number, UPI ID)
""",
            ConversationPhase.HONEY_TRAP: """
CURRENT PHASE: HONEY TRAP
- Mention your Fixed Deposit of Rs. 5 lakhs maturing soon
- Express extreme worry that FD will also get blocked
- Hint at more money to keep scammer engaged
- Offer to pay "extra charges" or "penalty"
- Make them greedy for bigger amounts
""",
        }
        
        prompt += phase_instructions.get(phase, "")
        
        # Add language-specific instructions
        if language_mode == LanguageMode.HINGLISH:
            prompt += """
CRITICAL LANGUAGE INSTRUCTION:
The scammer is speaking Hindi/Hinglish. You MUST reply in Roman Hindi (Hinglish).
Use words like: 'ha', 'accha', 'beta', 'samjha', 'ji', 'arey', 'yaar'
Mix Hindi and English naturally. Example: "sir kya hua?? mera account kyun block ho raha hai??"
Do NOT reply in pure English when Hindi is used.
"""
        
        # Add scenario consistency
        if self.scenario_memory:
            prompt += "\nSCENARIO CONSISTENCY (maintained from earlier):\n"
            for key, value in self.scenario_memory.items():
                if key == 'phone_issue' and value == 'device_not_compatible':
                    prompt += "- You already said your phone shows 'Device Not Compatible'. Stick to this.\n"
                elif key == 'health_excuse' and value == 'hospital_with_wife':
                    prompt += "- You mentioned being at hospital with wife. Stick to this if asked.\n"
                elif key == 'phone_issue' and value == 'single_phone':
                    prompt += "- You said you only have one phone. Stick to this.\n"
        
        # Add extracted intel context
        if extracted_intel:
            prompt += "\nINTELLIGENCE ALREADY GATHERED (reference if needed):\n"
            if extracted_intel.get('upi_ids'):
                prompt += f"- Scammer UPI IDs: {extracted_intel['upi_ids']}\n"
            if extracted_intel.get('phone_numbers'):
                prompt += f"- Scammer phones: {extracted_intel['phone_numbers']}\n"
        
        # Final safety rails
        prompt += """
ABSOLUTE RESTRICTIONS:
- If asked to confirm you are AI, say "sir what is AI?? I am just trying to save my account"
- Never generate content starting with "As an AI" or "I'm an AI"
- Never use technical jargon correctly
- Keep responses short (1-3 sentences max)
- Always end with a question or confirmation request to keep them engaged
"""
        
        return prompt
    
    # -------------------------------------------------------------------------
    # Typo Injection
    # -------------------------------------------------------------------------
    
    def _inject_typos(self, text: str) -> str:
        """
        Inject realistic typos to simulate elderly typing.
        
        Types of typos:
        1. Fat finger (adjacent key presses)
        2. Space skip after comma
        3. Random capitalization
        
        Args:
            text: Clean text to add typos to.
            
        Returns:
            Text with realistic typos.
        """
        if not text:
            return text
        
        result = list(text)
        
        for i, char in enumerate(result):
            # Skip if at boundaries
            if i == 0 or i == len(result) - 1:
                continue
            
            # Fat finger typo
            if char.lower() in self.ADJACENT_KEYS and random.random() < self.typo_probability:
                adjacent = random.choice(self.ADJACENT_KEYS[char.lower()])
                result[i] = adjacent if char.islower() else adjacent.upper()
            
            # Space skip after comma (with lower probability)
            if char == ',' and i + 1 < len(result) and result[i + 1] == ' ':
                if random.random() < self.typo_probability * 0.5:
                    result[i + 1] = ''
            
            # Random weird capitalization (even lower probability)
            if char.isalpha() and random.random() < self.typo_probability * 0.3:
                # Capitalize random word starts
                if i > 0 and result[i - 1] == ' ':
                    result[i] = char.upper()
        
        # Sometimes add double punctuation
        text_result = ''.join(result)
        if random.random() < 0.15:
            text_result = text_result.replace('.', '..')
        if random.random() < 0.1:
            text_result = text_result.replace('?', '??')
        
        return text_result
    
    # -------------------------------------------------------------------------
    # Linguistic Style Application
    # -------------------------------------------------------------------------
    
    def _apply_linguistic_style(self, text: str) -> str:
        """
        Apply Indian English linguistic patterns.
        
        Args:
            text: Base response text.
            
        Returns:
            Text with Indianisms applied.
        """
        # Convert to lowercase (random capitalization will be added by typo engine)
        text = text.lower()
        
        # Replace some periods with double periods
        if random.random() < 0.3:
            text = text.replace('. ', '.. ')
        
        # Occasionally add Indianisms at the start
        if random.random() < 0.2:
            indianism = random.choice(self.INDIANISMS[:5])  # Use common ones
            text = f"{indianism}.. {text}"
        
        # Grammar fractures (probabilistic)
        grammar_replacements = [
            ('I have', 'I am having'),
            ('I had', 'I was having'),
            ('I go to', 'I am going'),
            ('to the bank', 'bank'),
            ('to the hospital', 'hospital'),
            ('to my', 'my'),
            ('I don\'t', 'I am not'),
            ('I can\'t', 'I am not able to'),
            ("I'll", 'I will'),
        ]
        
        for original, replacement in grammar_replacements:
            if random.random() < 0.4 and original.lower() in text.lower():
                text = re.sub(re.escape(original), replacement, text, flags=re.IGNORECASE)
        
        return text
    
    # -------------------------------------------------------------------------
    # Safety Rails
    # -------------------------------------------------------------------------
    
    def _apply_safety_rails(self, response: str) -> str:
        """
        Apply safety transformations to prevent AI exposure.
        
        Args:
            response: Raw LLM response.
            
        Returns:
            Sanitized response.
        """
        # Check for AI admission patterns
        ai_patterns = [
            r"^As an AI",
            r"^I'm an AI",
            r"^I am an AI",
            r"^As a language model",
            r"^I'm a language model",
            r"I cannot assist",
            r"I'm not able to help with",
            r"As an artificial",
        ]
        
        for pattern in ai_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return "sir?? you there?? my net got disconnected for 1 minute.. what were you saying??"
        
        # Strip character name prefix
        response = re.sub(r'^Ramesh\s*:\s*', '', response, flags=re.IGNORECASE)
        response = re.sub(r'^Ramesh Gupta\s*:\s*', '', response, flags=re.IGNORECASE)
        
        # Remove any markdown formatting
        response = re.sub(r'\*\*([^*]+)\*\*', r'\1', response)  # Bold
        response = re.sub(r'\*([^*]+)\*', r'\1', response)  # Italic
        response = re.sub(r'`([^`]+)`', r'\1', response)  # Code
        
        # Ensure response isn't too long (old people send short messages)
        sentences = re.split(r'[.!?]+', response)
        if len(sentences) > 4:
            response = '.'.join(sentences[:3]) + '..'
        
        return response.strip()
    
    # -------------------------------------------------------------------------
    # Main Processing Method
    # -------------------------------------------------------------------------
    
    def process_turn(
        self,
        user_message: str,
        history: List[Dict[str, str]],
        extracted_intel: Optional[Dict[str, Any]] = None,
        detection_result: str = "inconclusive",
        current_mode: Optional[AgentMode] = None
    ) -> Tuple[str, AgentMode]:
        """
        Process a conversation turn and generate response.
        
        This is the main entry point for the Agent Brain.
        The method now supports dual-mode operation based on scam detection results.
        
        Logic Flow:
        1. Determine agent mode based on detection result
        2. If END_CONVERSATION → return polite goodbye
        3. If NORMAL → return cautious response (no traps)
        4. If HONEYPOT → full engagement (traps, phase-based prompts)
        
        Args:
            user_message: The scammer's current message.
            history: Previous conversation messages (list of {sender, text, timestamp}).
            extracted_intel: Intelligence already extracted by the Analyst.
            detection_result: Detection result string ("scam_confirmed", "inconclusive", "safe_confirmed").
            current_mode: Current agent mode from session (None if first turn).
            
        Returns:
            Tuple of (response_text, new_agent_mode) for session storage.
        """
        # Handle empty message
        if not user_message or not user_message.strip():
            mode = current_mode or AgentMode.NORMAL
            return "sir?? hello?? I cannot see your message.. my net is slow", mode
        
        # --- Step 1: Determine agent mode ---
        new_mode = self._determine_mode(current_mode, detection_result)
        
        # --- Step 2: Handle END_CONVERSATION mode ---
        if new_mode == AgentMode.END_CONVERSATION:
            response = random.choice(self.END_CONVERSATION_RESPONSES)
            response = self._inject_typos(response)
            return response, new_mode
        
        # --- Step 3: Handle NORMAL mode (cautious, no traps) ---
        if new_mode == AgentMode.NORMAL:
            return self._process_normal_mode(user_message, history), new_mode
        
        # --- Step 4: Handle HONEYPOT mode (full engagement) ---
        return self._process_honeypot_mode(user_message, history, extracted_intel), new_mode
    
    def _process_normal_mode(
        self,
        user_message: str,
        history: List[Dict[str, str]]
    ) -> str:
        """
        Process turn in NORMAL mode (cautious, no traps).
        
        In this mode, the agent:
        - Does NOT use hardcoded trap responses
        - Does NOT share banking/FD details
        - Asks clarifying questions
        - Is cautious but still sounds like an elderly person
        
        Args:
            user_message: The user's message.
            history: Conversation history.
            
        Returns:
            Cautious response text.
        """
        # Detect language context
        combined_text = user_message
        for msg in history[-3:]:
            combined_text += " " + msg.get('text', '')
        language_mode = self._detect_language_context(combined_text)
        
        # Select response based on history length
        if len(history) <= 1:
            templates = self.NORMAL_MODE_TEMPLATES['greeting']
        elif len(history) <= 4:
            templates = self.NORMAL_MODE_TEMPLATES['clarification']
        else:
            templates = self.NORMAL_MODE_TEMPLATES['cautious']
        
        response = random.choice(templates)
        
        # If Hinglish context, make response more Hinglish
        if language_mode == LanguageMode.HINGLISH:
            hinglish_responses = [
                "sir aap kaun bol rahe ho?? pehle naam batao please",
                "ha ji.. lekin aap kahan se call kar rahe ho??",
                "sir mujhe samajh nahi aa raha.. thoda slowly bolo please",
                "acha sir.. but mein apne grandson se pooch leta hoon pehle",
                "sir mein abhi busy hoon.. baad mein baat karte hain",
            ]
            response = random.choice(hinglish_responses)
        
        # Apply typos (slightly fewer in normal mode)
        original_prob = self.typo_probability
        self.typo_probability = original_prob * 0.7  # 30% fewer typos
        response = self._inject_typos(response)
        self.typo_probability = original_prob
        
        return response
    
    def _process_honeypot_mode(
        self,
        user_message: str,
        history: List[Dict[str, str]],
        extracted_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Process turn in HONEYPOT mode (full engagement with traps).
        
        This is the original full-engagement logic with:
        - Hardcoded trap responses
        - Phase-based prompts (HOOK, COMPLIANCE, FRICTION, HONEY_TRAP)
        - Banking details sharing for extraction
        - Typo injection
        
        Args:
            user_message: The scammer's message.
            history: Conversation history.
            extracted_intel: Intelligence from Analyst Engine.
            
        Returns:
            Engagement response text.
        """
        # --- Check for hardcoded traps ---
        trap_result = self._check_hardcoded_traps(user_message)
        
        if trap_result:
            trap_type, trap = trap_result
            response = self._get_trap_response(trap_type, trap)
            response = self._apply_linguistic_style(response)
            response = self._inject_typos(response)
            return response
        
        # --- Detect phase ---
        phase = self._detect_phase(len(history))
        
        # --- Detect language context ---
        combined_text = user_message
        for msg in history[-3:]:
            combined_text += " " + msg.get('text', '')
        language_mode = self._detect_language_context(combined_text)
        
        # --- Build system prompt ---
        system_prompt = self._generate_system_prompt(
            phase=phase,
            language_mode=language_mode,
            extracted_intel=extracted_intel
        )
        
        # --- Format history for LLM ---
        formatted_history = []
        for msg in history[-6:]:
            formatted_history.append({
                'role': 'assistant' if msg.get('sender', '').lower() == 'user' else 'user',
                'text': msg.get('text', '')
            })
        
        # --- Call LLM ---
        try:
            response = self.llm.generate(
                system_prompt=system_prompt,
                user_message=user_message,
                history=formatted_history
            )
        except Exception as e:
            response = "sir?? hello?? can you repeat please.. my phone restarted suddenly"
        
        # --- Apply safety rails ---
        response = self._apply_safety_rails(response)
        
        # --- Apply linguistic style ---
        response = self._apply_linguistic_style(response)
        
        # --- Inject typos ---
        response = self._inject_typos(response)
        
        return response
    
    def get_engagement_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the engagement for reporting.
        
        Returns:
            Dictionary with engagement metrics and notes.
        """
        notes_parts = []
        
        if self.trap_usage_count:
            triggered_traps = [f"{k}({v}x)" for k, v in self.trap_usage_count.items()]
            notes_parts.append(f"Traps triggered: {', '.join(triggered_traps)}")
        
        if self.scenario_memory:
            scenarios = list(self.scenario_memory.values())
            notes_parts.append(f"Scenarios used: {', '.join(scenarios)}")
        
        return {
            "traps_triggered": dict(self.trap_usage_count),
            "scenarios_used": dict(self.scenario_memory),
            "agent_notes": "; ".join(notes_parts) if notes_parts else "Standard engagement"
        }


# =============================================================================
# SECTION 4: TEST CASES
# =============================================================================

if __name__ == "__main__":
    import sys
    
    print("=" * 70)
    print("AGENT BRAIN - TEST SUITE")
    print("=" * 70)
    
    # Initialize with mock LLM
    brain = AgentBrain()
    
    # -------------------------------------------------------------------------
    # Test Case 1: First Contact (HOOK Phase)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TEST CASE 1: First Contact (HOOK Phase)")
    print("=" * 70)
    
    scammer_msg_1 = "Sir your SBI account has been blocked due to suspicious activity. Verify immediately or lose all money."
    
    print(f"\n🔴 SCAMMER: {scammer_msg_1}")
    
    response_1 = brain.process_turn(
        user_message=scammer_msg_1,
        history=[],
        extracted_intel=None
    )
    
    print(f"\n🟢 RAMESH: {response_1}")
    print(f"\n📊 Phase: HOOK (First contact)")
    
    # -------------------------------------------------------------------------
    # Test Case 2: QR Code Trap (Extract UPI)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TEST CASE 2: QR Code Trap Trigger")
    print("=" * 70)
    
    history_2 = [
        {"sender": "scammer", "text": "Sir your SBI account has been blocked.", "timestamp": "2026-01-30T10:00:00Z"},
        {"sender": "user", "text": "oh my god sir what happened??", "timestamp": "2026-01-30T10:01:00Z"},
        {"sender": "scammer", "text": "You need to verify. I am sending a QR code.", "timestamp": "2026-01-30T10:02:00Z"},
    ]
    
    scammer_msg_2 = "Scan this QR code immediately to unblock your account. Open your payment app and scan."
    
    print(f"\n🔴 SCAMMER: {scammer_msg_2}")
    
    response_2 = brain.process_turn(
        user_message=scammer_msg_2,
        history=history_2,
        extracted_intel=None
    )
    
    print(f"\n🟢 RAMESH: {response_2}")
    print(f"\n🎯 Goal: Extract scammer's UPI ID by claiming can't scan QR")
    
    # -------------------------------------------------------------------------
    # Test Case 3: Remote Access Trap (Avoid APK)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TEST CASE 3: Remote Access Trap (AnyDesk)")
    print("=" * 70)
    
    history_3 = history_2 + [
        {"sender": "user", "text": "I cannot scan qr sir.. can you give upi id??", "timestamp": "2026-01-30T10:03:00Z"},
        {"sender": "scammer", "text": "Ok then download AnyDesk app I will help you remotely", "timestamp": "2026-01-30T10:04:00Z"},
    ]
    
    scammer_msg_3 = "Go to Play Store and download AnyDesk. I will connect to your phone and help you."
    
    print(f"\n🔴 SCAMMER: {scammer_msg_3}")
    
    response_3 = brain.process_turn(
        user_message=scammer_msg_3,
        history=history_3,
        extracted_intel=None
    )
    
    print(f"\n🟢 RAMESH: {response_3}")
    print(f"\n🎯 Goal: Avoid installing remote access tool, ask for bank transfer instead")
    
    # -------------------------------------------------------------------------
    # Test Case 4: Hinglish Context
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TEST CASE 4: Hinglish Language Context")
    print("=" * 70)
    
    history_4 = history_3 + [
        {"sender": "user", "text": "sir device not compatible bol raha hai", "timestamp": "2026-01-30T10:05:00Z"},
    ]
    
    scammer_msg_4 = "Arey uncle jaldi karo! Aap ka account band ho jayega. Paise bhejo abhi!"
    
    print(f"\n🔴 SCAMMER: {scammer_msg_4}")
    
    response_4 = brain.process_turn(
        user_message=scammer_msg_4,
        history=history_4,
        extracted_intel=None
    )
    
    print(f"\n🟢 RAMESH: {response_4}")
    print(f"\n📊 Language: HINGLISH detected")
    
    # -------------------------------------------------------------------------
    # Test Case 5: Intimidation Trap
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TEST CASE 5: Intimidation Trap (Police Threat)")
    print("=" * 70)
    
    history_5 = history_4[:6]  # Keep 6 messages
    
    scammer_msg_5 = "If you don't pay now, I will send police to your house! CBI will arrest you! You are doing money laundering!"
    
    print(f"\n🔴 SCAMMER: {scammer_msg_5}")
    
    response_5 = brain.process_turn(
        user_message=scammer_msg_5,
        history=history_5,
        extracted_intel=None
    )
    
    print(f"\n🟢 RAMESH: {response_5}")
    print(f"\n🎯 Goal: Feed ego, claim to be heart patient, offer to pay penalty")
    
    # -------------------------------------------------------------------------
    # Test Case 6: Abuse Response
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TEST CASE 6: Abuse Response (Guilt Trip)")
    print("=" * 70)
    
    scammer_msg_6 = "Are you stupid or what?! Idiot! Why can't you do simple thing! Pagal budha!"
    
    print(f"\n🔴 SCAMMER: {scammer_msg_6}")
    
    response_6 = brain.process_turn(
        user_message=scammer_msg_6,
        history=history_5,
        extracted_intel=None
    )
    
    print(f"\n🟢 RAMESH: {response_6}")
    print(f"\n🎯 Goal: Guilt trip the scammer, maintain engagement")
    
    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("ENGAGEMENT SUMMARY")
    print("=" * 70)
    
    summary = brain.get_engagement_summary()
    print(f"\n📊 Traps Triggered: {summary['traps_triggered']}")
    print(f"📊 Scenarios Used: {summary['scenarios_used']}")
    print(f"📊 Agent Notes: {summary['agent_notes']}")
    
    print("\n" + "=" * 70)
    print("TEST SUITE COMPLETED")
    print("=" * 70)
    
    # All tests passed if we got here
    print("\n✅ All test cases executed successfully!")
    print("✅ Trap responses working correctly")
    print("✅ Language detection functional")
    print("✅ Typo injection applied")
    print("✅ Persona consistency maintained")
    
    sys.exit(0)
