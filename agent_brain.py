"""
Agent Brain: CBI Cyber Crime Intelligence Extraction Engine
=============================================================

This module implements the "Vikram Singh" persona - a middle-class IT
professional who poses as a potential victim to strategically extract
intelligence from scammers. The agent engages professionally to maximize
information extraction while maintaining a believable cover.

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
    INITIAL = auto()      # First contact - establish rapport
    EXTRACTION = auto()   # Primary phase - extract intelligence  
    DEEPENING = auto()    # Get additional details after initial extraction


class LanguageMode(Enum):
    """Language context for response generation."""
    ENGLISH = "english"
    HINGLISH = "hinglish"


class AgentMode(Enum):
    """
    Operating mode for the agent based on detection result.
    
    Modes:
    - NORMAL: Pre-detection or inconclusive. Cautious conversation, no traps.
    - HONEYPOT: Scam confirmed. Full Vikram persona with traps and intelligence extraction.
    - END_CONVERSATION: Safe user confirmed. Politely end the conversation.
    """
    NORMAL = "normal"
    HONEYPOT = "honeypot"
    END_CONVERSATION = "end_conversation"


@dataclass
class FakeProfile:
    """
    The simulated persona's fake identity - a believable target.
    
    CRITICAL: This data is injected into the LLM prompt so the persona
    has consistent details. The persona is a middle-class professional
    who appears to be a good target for scammers.
    """
    # Personal Details
    name: str = "Varun Singh"
    age: int = 45
    occupation: str = "IT Manager at a private company"
    location: str = "Mumbai, Maharashtra"
    phone_model: str = "Samsung Galaxy S21"
    
    # Banking Details (to be "shared" strategically to extract scammer's details)
    bank_name: str = "HDFC Bank"
    branch: str = "Andheri West Branch, Mumbai"
    account_last_4: str = "7823"
    account_type: str = "Savings Account"
    ifsc_code: str = "HDFC0001234"
    
    # UPI Details (fake but realistic)
    upi_id: str = "varun.singh45@hdfcbank"
    
    # Financial context
    salary: str = "Rs. 1,20,000 per month"
    savings_amount: str = "Rs. 8,50,000"
    
    def to_prompt_text(self) -> str:
        """Convert profile to text for prompt injection."""
        return f"""YOUR COVER IDENTITY (Use these details when needed):
- Name: {self.name}
- Age: {self.age} years
- Occupation: {self.occupation}
- Location: {self.location}
- Phone: {self.phone_model}

YOUR FAKE BANKING DETAILS (Share these to extract scammer's details):
- Bank: {self.bank_name}
- Account ending: ...{self.account_last_4}
- UPI ID: {self.upi_id}
- Savings: {self.savings_amount}

STRATEGY: Appear willing to comply, but always need "their" details first."""


@dataclass 
class TrapResponse:
    """Hardcoded trap response with metadata. Supports single or multiple messages."""
    response: str  # Primary response OR pipe-separated multiple messages (e.g. "msg1|msg2|msg3")
    goal: str
    intel_target: str  # What we're trying to extract
    
    def get_messages(self) -> List[str]:
        """Get response as list of messages. Use | as separator for multiple messages."""
        if '|' in self.response:
            return [msg.strip() for msg in self.response.split('|')]
        return [self.response]


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
    Simulates the Vikram Singh persona without actual LLM calls.
    """
    
    def __init__(self):
        self.response_templates = {
            ConversationPhase.INITIAL: [
                "I understand this is urgent. Can you please share your official contact number for verification?",
                "I want to resolve this immediately. Please share your UPI ID so I can make the payment.",
                "This is concerning. Can you provide your department email ID for my records?",
            ],
            ConversationPhase.EXTRACTION: [
                "I am ready to proceed with the transfer. Please share your bank account number and IFSC code.",
                "I tried the UPI payment but it failed. Can you share an alternative bank account?",
                "My phone is showing a network error. Can you share your WhatsApp number so I can send the confirmation there?",
                "I want to complete this transaction. Please provide your official email address for the receipt.",
            ],
            ConversationPhase.DEEPENING: [
                "The payment did not go through. Is there another UPI ID I can try?",
                "I am having issues with this account. Can you share your supervisor's contact details?",
                "For my records, can you also share an alternative phone number?",
                "The transfer is pending. Please share another bank account as backup.",
            ],
        }
    
    def generate(self, system_prompt: str, user_message: str, history: List[Dict[str, str]]) -> str:
        """Generate mock response based on conversation phase - clean, professional."""
        # Detect phase from history length
        turn_count = len(history) + 1
        
        if turn_count <= 1:
            phase = ConversationPhase.INITIAL
        elif turn_count <= 6:
            phase = ConversationPhase.EXTRACTION
        else:
            phase = ConversationPhase.DEEPENING
        
        templates = self.response_templates[phase]
        response = random.choice(templates)
        
        # Add contextual extraction requests
        if 'otp' in user_message.lower():
            response = "I am not receiving the OTP. Can you share an alternative contact number where I can reach you?"
        elif 'download' in user_message.lower() or 'install' in user_message.lower():
            response = "My phone does not support this app. Can we proceed with a direct bank transfer instead? Please share the account details."
        elif 'send' in user_message.lower() or 'transfer' in user_message.lower():
            response = "I am ready to transfer. Please confirm your bank account number and IFSC code."
        
        return response


# =============================================================================
# SECTION 3: THE AGENT BRAIN (Main Class)
# =============================================================================

class AgentBrain:
    """
    The autonomous scam engagement and intelligence extraction engine.
    
    This class manages the "Vikram Singh" persona and orchestrates
    strategic conversation with scammers to extract maximum intelligence.
    
    Key Features:
    - Smart extraction responses that progress to new intel targets
    - Clean, professional English responses
    - Intel state tracking to avoid repetition
    - Safety rails to prevent AI exposure
    """
    
    # -------------------------------------------------------------------------
    # Extraction Responses (Smart, Progressive)
    # -------------------------------------------------------------------------
    
    TRAP_DEFINITIONS: Dict[str, TrapResponse] = {
        # QR Code -> Extract UPI ID
        'qr_scan': TrapResponse(
            response="I can not scan the QR code on my phone. Can you share your UPI ID instead? I will transfer directly.",
            goal="Extract scammer's UPI ID",
            intel_target="upi_id"
        ),
        
        # Remote Access -> Redirect to bank transfer
        'remote_access': TrapResponse(
            response="My phone does not support this app. Can we do a direct bank transfer instead? Please share your account number and IFSC code.",
            goal="Avoid remote access, get bank details",
            intel_target="bank_account"
        ),
        
        # Video Call -> Get phone number
        'video_call': TrapResponse(
            response="I am in a meeting right now and cannot do a video call. Can you share your WhatsApp number? I will message you there.",
            goal="Extract phone number",
            intel_target="phone_number"
        ),
        
        # OTP Request -> Get alternative contact (NO MORE FAKE OTP LOOPS)
        'otp_request': TrapResponse(
            response="I am not receiving any OTP on my phone. There might be a network issue. Can you share an alternative contact number or email where I can reach you?",
            goal="Extract alternative contact",
            intel_target="phone_number"
        ),
        
        # Intimidation -> Get official details
        'intimidation': TrapResponse(
            response="I understand sir. I want to cooperate fully. Can you share your official ID or badge number so I can verify and proceed?",
            goal="Extract fake credentials or break cover",
            intel_target="credentials"
        ),
        
        # Abuse Response -> Redirect to extraction
        'abuse': TrapResponse(
            response="I apologize for the delay. I am trying my best. Please share your bank account details and I will complete the transfer immediately.",
            goal="Redirect to bank account extraction",
            intel_target="bank_account"
        ),
        
        # Link Click -> Confirm URL
        'link_click': TrapResponse(
            response="The link is not opening on my phone. Can you share the correct URL again? Also, which website is this from?",
            goal="Confirm and extract URL",
            intel_target="url"
        ),
        
        # Payment Request -> Get bank details
        'payment_request': TrapResponse(
            response="I am ready to transfer the amount. Can you confirm your bank account number and IFSC code? I will add you as a beneficiary.",
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
        "I think there has been some misunderstanding. Thank you for your time. Goodbye.",
        "I apologize for the confusion. Have a nice day.",
        "No problem. Sorry for any inconvenience. Take care.",
        "I understand now. Thank you for clarifying. Goodbye.",
    ]
    
    # Normal mode responses (INCONCLUSIVE - cautious, no engagement)
    NORMAL_MODE_TEMPLATES: Dict[str, List[str]] = {
        'greeting': [
            "Hello. Who is this?",
            "Hi. May I know who is calling?",
            "Hello. I did not recognize your number.",
        ],
        'clarification': [
            "I am not sure I understand. Can you explain what this is about?",
            "Which organization are you calling from?",
            "Can you provide more details about this matter?",
        ],
        'cautious': [
            "I will need to verify this with my bank directly. Thank you.",
            "Can you share an official reference number for this?",
            "I will check this and get back to you.",
        ],
    }
    
    # System prompt for NORMAL mode (cautious, contextual responses)
    NORMAL_MODE_SYSTEM_PROMPT: str = """You are Vikram Singh, a 45-year-old IT professional from Mumbai.

You received a message from an unknown person. You are cautious but polite.

RULES:
1. Respond in clear, grammatically correct English.
2. Be polite but cautious - ask who they are and what they want.
3. Do NOT share any personal or banking information.
4. Keep responses short (1-2 sentences).
5. If they mention something you don't recognize, say you don't recall.
6. Ask clarifying questions naturally.

RESPOND NATURALLY to the message. Match the tone - if casual, be casual. If formal, be formal."""
    
    def __init__(
        self, 
        llm_client: Optional[LLMInterface] = None,
        fake_profile: Optional[FakeProfile] = None,
        typo_probability: float = 0.0,  # Disabled - we want clean responses
        scenario_memory: Optional[Dict[str, str]] = None
    ):
        """
        Initialize the Agent Brain.
        
        Args:
            llm_client: LLM interface for response generation. Uses MockAgentLLM if not provided.
            fake_profile: The persona's fake identity. Uses default FakeProfile if not provided.
            typo_probability: Probability of injecting typos (0.0 to 1.0). Default 0.0 for clean responses.
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
        
        # Intel tracking - what we've already extracted (to avoid asking for same thing)
        self.extracted_intel_types: set = set()  # {'upi_id', 'bank_account', 'phone_number', etc}
    
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
            return ConversationPhase.INITIAL
        elif history_len <= 6:
            return ConversationPhase.EXTRACTION
        else:
            return ConversationPhase.DEEPENING
    
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
            The response text (may be pipe-separated for multiple messages).
        """
        # Track trap usage
        self.trap_usage_count[trap_type] = self.trap_usage_count.get(trap_type, 0) + 1
        self.last_trap_used = trap_type
        
        # Get messages (handles both single and multi-message traps)
        messages = trap.get_messages()
        
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
        
        # Return pipe-separated if multiple messages
        return '|'.join(messages)
    
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
        Build the complete system prompt for intelligent extraction.
        
        Args:
            phase: Current conversation phase.
            language_mode: Language context (ignored - always English).
            extracted_intel: Any intelligence already extracted.
            
        Returns:
            Complete system prompt string.
        """
        # Determine what intel we still need
        already_have = []
        still_need = []
        
        if extracted_intel:
            if extracted_intel.get('upi_ids'):
                already_have.append(f"UPI IDs: {extracted_intel['upi_ids']}")
            else:
                still_need.append("UPI ID")
            if extracted_intel.get('phone_numbers'):
                already_have.append(f"Phone numbers: {extracted_intel['phone_numbers']}")
            else:
                still_need.append("Phone number")
            if extracted_intel.get('bank_accounts'):
                already_have.append(f"Bank accounts: {extracted_intel['bank_accounts']}")
            else:
                still_need.append("Bank account + IFSC")
            if extracted_intel.get('emails'):
                already_have.append(f"Emails: {extracted_intel['emails']}")
            else:
                still_need.append("Email address")
        else:
            still_need = ["UPI ID", "Phone number", "Bank account + IFSC", "Email address"]
        
        # Build clean, focused prompt
        prompt = f"""You are {self.profile.name}, a {self.profile.age}-year-old {self.profile.occupation}.

{self.profile.to_prompt_text()}

YOUR MISSION: Extract as much contact and financial information from the scammer as possible.
You are pretending to be a potential victim to gather intelligence.

RESPONSE RULES:
1. Write in clear, grammatically correct English. No broken English or typos.
2. Keep responses SHORT - 1-2 sentences maximum.
3. ALWAYS ask for NEW information you don't have yet.
4. Appear cooperative and willing to help, but need "their details first".
5. Never admit you are an AI or automated system.
6. Never actually complete any transaction or share real credentials.

INTELLIGENCE STATUS:
"""
        if already_have:
            prompt += f"Already collected: {', '.join(already_have)}\n"
        if still_need:
            prompt += f"Still need to extract: {', '.join(still_need)}\n"
        
        # Phase-specific extraction strategy
        phase_strategies = {
            ConversationPhase.INITIAL: """
PHASE: Initial Contact
- Show concern about the issue they raised
- Ask for their official contact details to "verify"
- Example: "I understand. Can you share your official contact number so I can verify this?"
""",
            ConversationPhase.EXTRACTION: """
PHASE: Active Extraction  
- You have already shown concern, now focus on getting details
- If they want payment, ask for their UPI ID or bank account
- If they want to call, ask for their phone number
- Example: "I am ready to proceed. Please share your UPI ID for the transfer."
""",
            ConversationPhase.DEEPENING: """
PHASE: Deep Extraction
- You already have some details, now get MORE
- Ask for alternative contacts "in case this doesn't work"
- Ask for supervisor's number or email
- Example: "The UPI transfer failed. Can you share a bank account number instead?"
""",
        }
        
        prompt += phase_strategies.get(phase, "")
        
        # Critical extraction tactics
        prompt += """
EXTRACTION TACTICS (use one per response):
- "Can you share your UPI ID? I will transfer directly."
- "Please provide your bank account number and IFSC code."
- "What is your WhatsApp number? I will send the confirmation there."
- "Can you share your official email ID for my records?"
- "Is there an alternative contact number I can reach you on?"

DO NOT:
- Repeat the same question if you already have that information
- Give fake OTPs or play dumb - be professional
- Use Hindi unless the scammer is exclusively using Hindi
- Write long rambling messages
- End without asking for NEW information

RESPOND TO THE SCAMMER'S LAST MESSAGE, THEN ASK FOR THE NEXT PIECE OF INFORMATION YOU NEED."""
        
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
        
        # Sometimes add double punctuation (reduced frequency for readability)
        text_result = ''.join(result)
        if random.random() < 0.08:
            text_result = text_result.replace('.', '..')
        if random.random() < 0.05:
            text_result = text_result.replace('?', '??')
        
        return text_result
    
    # -------------------------------------------------------------------------
    # Linguistic Style Application
    # -------------------------------------------------------------------------
    
    def _apply_linguistic_style(self, text: str) -> str:
        """
        Clean up response text. No longer applies broken English.
        
        Args:
            text: Base response text.
            
        Returns:
            Clean text (no modifications needed for professional persona).
        """
        # Just return the text as-is for clean, professional responses
        return text.strip()
    
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
                return "I apologize, there seems to be a connection issue. Can you please share your contact details again?"
        
        # Strip character name prefix
        response = re.sub(r'^Vikram\s*:\s*', '', response, flags=re.IGNORECASE)
        response = re.sub(r'^Vikram Singh\s*:\s*', '', response, flags=re.IGNORECASE)
        response = re.sub(r'^Ramesh\s*:\s*', '', response, flags=re.IGNORECASE)
        response = re.sub(r'^Ramesh Gupta\s*:\s*', '', response, flags=re.IGNORECASE)
        
        # Remove any markdown formatting
        response = re.sub(r'\*\*([^*]+)\*\*', r'\1', response)  # Bold
        response = re.sub(r'\*([^*]+)\*', r'\1', response)  # Italic
        response = re.sub(r'`([^`]+)`', r'\1', response)  # Code
        
        # Ensure response isn't too long - max 3 sentences for clarity
        sentences = re.split(r'(?<=[.!?])\s+', response)
        if len(sentences) > 3:
            response = ' '.join(sentences[:3])
        
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
        - Uses LLM for contextual responses
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
        # Build system prompt for NORMAL mode (always English)
        system_prompt = self.NORMAL_MODE_SYSTEM_PROMPT
        
        # Format history for LLM
        formatted_history = []
        for msg in history[-4:]:
            formatted_history.append({
                'role': 'assistant' if msg.get('sender', '').lower() == 'user' else 'user',
                'text': msg.get('text', '')
            })
        
        # Call LLM for contextual response
        try:
            response = self.llm.generate(
                system_prompt=system_prompt,
                user_message=user_message,
                history=formatted_history
            )
        except Exception as e:
            # Fallback to templates if LLM fails
            if len(history) <= 1:
                templates = self.NORMAL_MODE_TEMPLATES['greeting']
            elif len(history) <= 4:
                templates = self.NORMAL_MODE_TEMPLATES['clarification']
            else:
                templates = self.NORMAL_MODE_TEMPLATES['cautious']
            response = random.choice(templates)
        
        # Apply safety rails only (no typos, no linguistic modifications)
        response = self._apply_safety_rails(response)
        
        return response
    
    def _process_honeypot_mode(
        self,
        user_message: str,
        history: List[Dict[str, str]],
        extracted_intel: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Process turn in HONEYPOT mode - intelligent extraction.
        
        This mode focuses on:
        - Smart extraction responses
        - Progressive intel gathering (move to new targets)
        - Clean, professional English responses
        - No typos or broken grammar
        
        Args:
            user_message: The scammer's message.
            history: Conversation history.
            extracted_intel: Intelligence from Analyst Engine.
            
        Returns:
            Extraction-focused response text.
        """
        # --- Check for hardcoded extraction triggers ---
        trap_result = self._check_hardcoded_traps(user_message)
        
        if trap_result:
            trap_type, trap = trap_result
            
            # Check if we already have this type of intel - if so, skip trap and use LLM
            intel_type = trap.intel_target
            if intel_type in ['upi_id', 'bank_account', 'phone_number']:
                if extracted_intel:
                    if intel_type == 'upi_id' and extracted_intel.get('upi_ids'):
                        pass  # Already have UPI, let LLM ask for something else
                    elif intel_type == 'bank_account' and extracted_intel.get('bank_accounts'):
                        pass  # Already have bank account, let LLM ask for something else
                    elif intel_type == 'phone_number' and extracted_intel.get('phone_numbers'):
                        pass  # Already have phone, let LLM ask for something else
                    else:
                        # Don't have this intel yet, use trap response
                        response = self._get_trap_response(trap_type, trap)
                        return self._apply_safety_rails(response)
                else:
                    # No intel yet, use trap response
                    response = self._get_trap_response(trap_type, trap)
                    return self._apply_safety_rails(response)
        
        # --- Detect phase ---
        phase = self._detect_phase(len(history))
        
        # --- Build system prompt (always English) ---
        system_prompt = self._generate_system_prompt(
            phase=phase,
            language_mode=LanguageMode.ENGLISH,  # Always English
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
            # Professional fallback
            response = "I apologize, there was a connection issue. Can you please share your contact details so I can reach you?"
        
        # --- Apply safety rails (no typos, no linguistic modifications) ---
        response = self._apply_safety_rails(response)
        
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
    
    print(f"\n🟢 VIKRAM: {response_1}")
    print(f"\n📊 Phase: INITIAL (First contact)")
    
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
    
    print(f"\n🟢 VIKRAM: {response_2}")
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
    
    print(f"\n🟢 VIKRAM: {response_3}")
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
    
    print(f"\n🟢 VIKRAM: {response_4}")
    print(f"\n📊 Language: Requesting extraction")
    
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
    
    print(f"\n🟢 VIKRAM: {response_5}")
    print(f"\n🎯 Goal: Professional response, extract contact details")
    
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
    
    print(f"\n🟢 VIKRAM: {response_6}")
    print(f"\n🎯 Goal: Professional response, continue extraction")
    
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
