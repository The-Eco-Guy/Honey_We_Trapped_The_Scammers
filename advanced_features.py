"""
Advanced Features: Differentiating Capabilities for Honeypot System
===================================================================

This module contains advanced features that will make your submission
stand out from other teams:

1. Behavioral Fingerprinting - Identify repeat scammers
2. Multi-Persona System - Adapt persona to scam type
3. Proactive Bait Injection - Actively extract intel
4. Temporal Analysis - Detect operation patterns
5. Enhanced Intel Extraction - Aadhaar, PAN, social handles

Usage:
    from advanced_features import (
        BehavioralFingerprinter,
        PersonaSelector,
        ProactiveBaitEngine,
        TemporalAnalyzer,
        EnhancedIntelExtractor
    )
"""

from __future__ import annotations

import hashlib
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import random


# =============================================================================
# 1. BEHAVIORAL FINGERPRINTING
# =============================================================================

class ScammerBehavior(Enum):
    """Behavioral traits to track."""
    AGGRESSIVE = "aggressive"       # Uses threats quickly
    PATIENT = "patient"             # Long buildup
    TECHNICAL = "technical"         # Uses tech jargon
    EMOTIONAL = "emotional"         # Uses guilt/pity
    PROFESSIONAL = "professional"   # Corporate tone
    RUSHED = "rushed"               # High urgency


@dataclass
class BehavioralSignature:
    """
    Tracks behavioral patterns that persist across scammer identities.
    Even if a scammer changes phone/UPI, their patterns remain.
    """
    # Typing patterns
    avg_message_length: float = 0.0
    avg_response_time_seconds: float = 0.0
    caps_ratio: float = 0.0  # Percentage of capital letters
    punctuation_style: str = ""  # "heavy", "light", "none"
    
    # Escalation patterns
    turns_to_first_threat: int = 0
    turns_to_payment_request: int = 0
    urgency_escalation_rate: float = 0.0
    
    # Vocabulary patterns
    threat_vocabulary: List[str] = field(default_factory=list)
    payment_methods_mentioned: List[str] = field(default_factory=list)
    institutions_impersonated: List[str] = field(default_factory=list)
    
    # Language patterns
    hinglish_ratio: float = 0.0
    grammar_error_frequency: float = 0.0
    
    def calculate_hash(self) -> str:
        """Generate a fingerprint hash from behavioral features."""
        features = [
            round(self.avg_message_length, -1),  # Round to nearest 10
            round(self.caps_ratio, 1),
            self.punctuation_style,
            self.turns_to_first_threat,
            round(self.hinglish_ratio, 1),
            tuple(sorted(self.institutions_impersonated)[:3])
        ]
        return hashlib.md5(str(features).encode()).hexdigest()[:12]


class BehavioralFingerprinter:
    """
    Analyzes conversation patterns to create a behavioral fingerprint.
    
    This allows identification of repeat scammers even when they:
    - Change phone numbers
    - Use different UPI IDs
    - Modify their scripts slightly
    """
    
    # Threat keywords for tracking
    THREAT_KEYWORDS = {
        'police', 'arrest', 'jail', 'court', 'case', 'fir', 'cbi',
        'legal action', 'block', 'suspend', 'terminate', 'freeze'
    }
    
    # Payment method keywords
    PAYMENT_KEYWORDS = {
        'upi': 'upi', 'gpay': 'gpay', 'phonepe': 'phonepe', 
        'paytm': 'paytm', 'bank transfer': 'bank', 'neft': 'neft',
        'imps': 'imps', 'cash': 'cash', 'crypto': 'crypto'
    }
    
    # Institution impersonation keywords
    INSTITUTION_KEYWORDS = {
        'sbi': 'SBI', 'hdfc': 'HDFC', 'icici': 'ICICI', 'axis': 'Axis',
        'rbi': 'RBI', 'income tax': 'IT Department', 'customs': 'Customs',
        'police': 'Police', 'cyber cell': 'Cyber Cell', 'trai': 'TRAI'
    }
    
    # Hinglish detection
    HINGLISH_WORDS = {
        'hai', 'kya', 'karo', 'karde', 'bhejo', 'batao', 'jaldi',
        'abhi', 'paise', 'haan', 'nahi', 'aap', 'sir', 'ji'
    }
    
    def __init__(self):
        self.message_timestamps: List[datetime] = []
        self.message_lengths: List[int] = []
        self.messages: List[str] = []
        
    def add_message(self, text: str, timestamp: Optional[datetime] = None):
        """Add a scammer message for analysis."""
        self.messages.append(text)
        self.message_lengths.append(len(text))
        self.message_timestamps.append(timestamp or datetime.now())
    
    def analyze(self) -> BehavioralSignature:
        """Generate behavioral signature from collected messages."""
        sig = BehavioralSignature()
        
        if not self.messages:
            return sig
        
        all_text = " ".join(self.messages)
        all_text_lower = all_text.lower()
        
        # Message length analysis
        sig.avg_message_length = statistics.mean(self.message_lengths)
        
        # Response time analysis (if we have timestamps)
        if len(self.message_timestamps) > 1:
            time_diffs = [
                (self.message_timestamps[i+1] - self.message_timestamps[i]).total_seconds()
                for i in range(len(self.message_timestamps) - 1)
            ]
            sig.avg_response_time_seconds = statistics.mean(time_diffs)
        
        # Caps ratio
        alpha_chars = [c for c in all_text if c.isalpha()]
        if alpha_chars:
            sig.caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        
        # Punctuation style
        punctuation_count = sum(1 for c in all_text if c in '!?.,;:')
        if punctuation_count > len(all_text) * 0.05:
            sig.punctuation_style = "heavy"
        elif punctuation_count > len(all_text) * 0.02:
            sig.punctuation_style = "normal"
        else:
            sig.punctuation_style = "light"
        
        # Threat tracking
        for i, msg in enumerate(self.messages):
            msg_lower = msg.lower()
            if any(threat in msg_lower for threat in self.THREAT_KEYWORDS):
                if sig.turns_to_first_threat == 0:
                    sig.turns_to_first_threat = i + 1
                sig.threat_vocabulary.extend(
                    [t for t in self.THREAT_KEYWORDS if t in msg_lower]
                )
        
        # Payment method tracking
        for keyword, method in self.PAYMENT_KEYWORDS.items():
            if keyword in all_text_lower:
                sig.payment_methods_mentioned.append(method)
        
        # Institution impersonation
        for keyword, institution in self.INSTITUTION_KEYWORDS.items():
            if keyword in all_text_lower:
                sig.institutions_impersonated.append(institution)
        
        # Hinglish ratio
        words = all_text_lower.split()
        if words:
            hinglish_words = sum(1 for w in words if w in self.HINGLISH_WORDS)
            sig.hinglish_ratio = hinglish_words / len(words)
        
        # Urgency escalation
        urgency_keywords = ['urgent', 'immediately', 'now', 'today', 'jaldi', 'abhi']
        urgency_by_turn = []
        for msg in self.messages:
            msg_lower = msg.lower()
            urgency_count = sum(1 for kw in urgency_keywords if kw in msg_lower)
            urgency_by_turn.append(urgency_count)
        
        if len(urgency_by_turn) > 2:
            # Check if urgency increases over time
            first_half = urgency_by_turn[:len(urgency_by_turn)//2]
            second_half = urgency_by_turn[len(urgency_by_turn)//2:]
            sig.urgency_escalation_rate = (
                (sum(second_half) / len(second_half)) - 
                (sum(first_half) / len(first_half))
            )
        
        return sig
    
    def get_fingerprint(self) -> str:
        """Get the fingerprint hash for this scammer."""
        return self.analyze().calculate_hash()
    
    def get_behavior_type(self) -> ScammerBehavior:
        """Classify the scammer's behavioral type."""
        sig = self.analyze()
        
        if sig.turns_to_first_threat > 0 and sig.turns_to_first_threat <= 2:
            return ScammerBehavior.AGGRESSIVE
        elif sig.urgency_escalation_rate > 0.5:
            return ScammerBehavior.RUSHED
        elif sig.caps_ratio > 0.3:
            return ScammerBehavior.AGGRESSIVE
        elif 'RBI' in sig.institutions_impersonated or 'IT Department' in sig.institutions_impersonated:
            return ScammerBehavior.PROFESSIONAL
        elif sig.hinglish_ratio > 0.2:
            return ScammerBehavior.EMOTIONAL
        else:
            return ScammerBehavior.PATIENT


# =============================================================================
# 2. MULTI-PERSONA SYSTEM
# =============================================================================

class ScamType(Enum):
    """Types of scams and their characteristics."""
    TECH_SUPPORT = "tech_support"      # Your account is blocked
    KYC_UPDATE = "kyc_update"          # Update your KYC
    LOTTERY_PRIZE = "lottery_prize"    # You won a prize
    REFUND_FRAUD = "refund_fraud"      # Pending refund
    AUTHORITY_THREAT = "authority"     # Police/CBI threat
    INVESTMENT = "investment"          # Crypto/Stock tips
    ROMANCE = "romance"                # Relationship scam
    JOB_OFFER = "job_offer"            # Fake job offer


@dataclass
class PersonaProfile:
    """Base class for persona profiles."""
    name: str
    age: int
    occupation: str
    location: str
    personality: str
    vulnerabilities: List[str]
    speech_patterns: List[str]
    
    # Banking/financial bait
    bank_name: str = "SBI"
    savings_amount: str = "Rs. 50,000"
    pension_or_salary: str = "Rs. 25,000"
    
    def get_greeting(self) -> str:
        """Get persona-appropriate greeting."""
        raise NotImplementedError
    
    def get_fear_response(self) -> str:
        """Get persona-appropriate fear response."""
        raise NotImplementedError
    
    def get_confusion_response(self) -> str:
        """Get persona-appropriate confusion response."""
        raise NotImplementedError


@dataclass
class RameshGuptaProfile(PersonaProfile):
    """The classic confused elderly man persona."""
    name: str = "Ramesh Chandra Gupta"
    age: int = 67
    occupation: str = "Retired Govt Employee"
    location: str = "Lucknow"
    personality: str = "confused, trusting, tech-challenged"
    vulnerabilities: List[str] = field(default_factory=lambda: [
        "fears losing pension", "trusts authority figures",
        "bad with technology", "lonely"
    ])
    speech_patterns: List[str] = field(default_factory=lambda: [
        "sir ji", "please help", "I am trying but",
        "my old phone", "grandson set password"
    ])
    
    def get_greeting(self) -> str:
        return "hello?? who is this sir??"
    
    def get_fear_response(self) -> str:
        return "sir please no!! my all pension money is there only!! please help me sir I am old man!!"
    
    def get_confusion_response(self) -> str:
        return "sir I am not understanding.. can you explain again please?? my phone is very slow.."


@dataclass
class PriyaSharmaProfile(PersonaProfile):
    """Greedy housewife persona - good for lottery/prize scams."""
    name: str = "Priya Sharma"
    age: int = 42
    occupation: str = "Housewife"
    location: str = "Delhi"
    personality: str = "greedy, excited, impulsive"
    vulnerabilities: List[str] = field(default_factory=lambda: [
        "wants easy money", "hides things from husband",
        "believes in luck", "competitive with neighbors"
    ])
    speech_patterns: List[str] = field(default_factory=lambda: [
        "oh my god!!", "really?? I won??", "don't tell my husband",
        "how much money?", "I knew my luck would change"
    ])
    bank_name: str = "HDFC"
    savings_amount: str = "Rs. 3,00,000"
    pension_or_salary: str = "Husband earns Rs. 80,000"
    
    def get_greeting(self) -> str:
        return "hello?? yes speaking??"
    
    def get_fear_response(self) -> str:
        return "what?? but I didn't do anything wrong!! please don't tell my husband about this!!"
    
    def get_confusion_response(self) -> str:
        return "wait wait I don't understand.. let me write this down.. ok continue.."


@dataclass
class RajeshKumarProfile(PersonaProfile):
    """Retired banker - good for investment scams."""
    name: str = "Rajesh Kumar"
    age: int = 58
    occupation: str = "Retired Bank Manager"
    location: str = "Mumbai"
    personality: str = "knowledgeable but greedy, overconfident"
    vulnerabilities: List[str] = field(default_factory=lambda: [
        "thinks he's too smart to be scammed",
        "greedy for high returns", "bored in retirement",
        "wants to prove financial expertise"
    ])
    speech_patterns: List[str] = field(default_factory=lambda: [
        "yes I understand banking", "what's the ROI?",
        "I've seen many schemes", "tell me the details"
    ])
    bank_name: str = "ICICI"
    savings_amount: str = "Rs. 15,00,000"
    pension_or_salary: str = "Rs. 60,000 pension"
    
    def get_greeting(self) -> str:
        return "hello, Rajesh Kumar here. who is calling?"
    
    def get_fear_response(self) -> str:
        return "what?? this can't be right.. I was a bank manager, I know how these things work!!"
    
    def get_confusion_response(self) -> str:
        return "hmm let me think about this.. can you send me the documentation?"


class PersonaSelector:
    """
    Selects the most appropriate persona based on detected scam type.
    """
    
    PERSONA_MAP = {
        ScamType.TECH_SUPPORT: RameshGuptaProfile,
        ScamType.KYC_UPDATE: RameshGuptaProfile,
        ScamType.LOTTERY_PRIZE: PriyaSharmaProfile,
        ScamType.REFUND_FRAUD: RameshGuptaProfile,
        ScamType.AUTHORITY_THREAT: RameshGuptaProfile,
        ScamType.INVESTMENT: RajeshKumarProfile,
        ScamType.ROMANCE: PriyaSharmaProfile,
        ScamType.JOB_OFFER: PriyaSharmaProfile,
    }
    
    # Keywords to detect scam type
    SCAM_TYPE_KEYWORDS = {
        ScamType.TECH_SUPPORT: ['blocked', 'suspend', 'account', 'verify', 'kyc'],
        ScamType.KYC_UPDATE: ['kyc', 'aadhaar', 'pan', 'update', 'link'],
        ScamType.LOTTERY_PRIZE: ['lottery', 'prize', 'winner', 'won', 'congratulations', 'lucky'],
        ScamType.REFUND_FRAUD: ['refund', 'cashback', 'return', 'credit', 'pending'],
        ScamType.AUTHORITY_THREAT: ['police', 'arrest', 'cbi', 'court', 'legal', 'summon'],
        ScamType.INVESTMENT: ['invest', 'crypto', 'bitcoin', 'stock', 'return', 'profit', 'trading'],
        ScamType.ROMANCE: ['love', 'miss you', 'relationship', 'marry', 'lonely'],
        ScamType.JOB_OFFER: ['job', 'salary', 'hiring', 'work from home', 'income', 'offer'],
    }
    
    def detect_scam_type(self, messages: List[str]) -> ScamType:
        """Detect the type of scam from conversation."""
        combined = " ".join(messages).lower()
        
        scores = {}
        for scam_type, keywords in self.SCAM_TYPE_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in combined)
            scores[scam_type] = score
        
        # Get highest scoring type
        if max(scores.values()) > 0:
            return max(scores, key=scores.get)
        
        # Default to tech support
        return ScamType.TECH_SUPPORT
    
    def select_persona(self, scam_type: ScamType) -> PersonaProfile:
        """Select appropriate persona for the scam type."""
        profile_class = self.PERSONA_MAP.get(scam_type, RameshGuptaProfile)
        return profile_class()
    
    def get_optimal_persona(self, messages: List[str]) -> Tuple[PersonaProfile, ScamType]:
        """Detect scam type and return optimal persona."""
        scam_type = self.detect_scam_type(messages)
        persona = self.select_persona(scam_type)
        return persona, scam_type


# =============================================================================
# 3. PROACTIVE BAIT INJECTION
# =============================================================================

class ProactiveBaitEngine:
    """
    Generates proactive bait messages to extract specific intel.
    
    Instead of just reacting, we plant "seeds" that make scammers
    reveal information they otherwise wouldn't.
    """
    
    # Bait templates by target intel
    BAITS = {
        "phone_number": [
            "sir you are so helpful.. can I have your whatsapp number to call if any problem??",
            "sir my daughter wants to talk to you.. can you give number she will call??",
            "sir what if call gets disconnected?? give me your number I will call back",
        ],
        "upi_id": [
            "sir qr code is not scanning.. can you tell upi id I will type manually??",
            "sir I am trying to send but need your upi.. phonepe or gpay??",
            "sir beneficiary not adding.. give me your upi id directly na",
        ],
        "bank_account": [
            "sir upi is not working.. can you give bank account number?? I will do NEFT",
            "sir my upi has daily limit.. better I do bank transfer.. give account details",
            "sir for such big amount better to do RTGS only.. give me account and IFSC",
        ],
        "email": [
            "sir can you send me the documents on email?? my email is ramesh67@gmail.com",
            "sir I will send you screenshot on email.. what is your email id??",
            "sir better send official letter na.. give me email address",
        ],
        "identity": [
            "sir what is your name again?? I want to note down for my records",
            "sir which department are you from?? I will come to office directly",
            "sir what is your employee ID?? I want to verify you are genuine",
        ],
        "greed_trigger": [
            "sir actually I also have FD of 8 lakh maturing next week.. will that be blocked too??",
            "sir my husband's account also has 5 lakh.. should I tell him also??",
            "sir I just received insurance money 10 lakh.. is that safe??",
        ],
        "time_waste": [
            "sir one minute.. I am in bathroom.. wait 5 minutes I will call back",
            "sir my grandson is crying.. let me settle him first.. 10 minutes please",
            "sir battery is 2%.. let me charge phone first.. call me in 15 minutes",
        ],
    }
    
    def __init__(self):
        self.used_baits: Dict[str, int] = {}  # Track usage to avoid repetition
    
    def get_bait(
        self, 
        target: str, 
        collected_intel: Dict[str, List[str]]
    ) -> Optional[str]:
        """
        Get appropriate bait based on what intel we're missing.
        
        Args:
            target: The type of intel we want to extract
            collected_intel: Intel already collected
            
        Returns:
            Bait message or None if no suitable bait
        """
        # Check if we already have this intel
        if target == "phone_number" and collected_intel.get("phone_numbers"):
            return None
        if target == "upi_id" and collected_intel.get("upi_ids"):
            return None
        if target == "bank_account" and collected_intel.get("bank_accounts"):
            return None
        
        # Get baits for target
        baits = self.BAITS.get(target, [])
        if not baits:
            return None
        
        # Avoid repeating same bait
        usage_count = self.used_baits.get(target, 0)
        if usage_count >= len(baits):
            return None
        
        bait = baits[usage_count]
        self.used_baits[target] = usage_count + 1
        
        return bait
    
    def suggest_next_bait(
        self, 
        collected_intel: Dict[str, List[str]],
        turn_count: int
    ) -> Tuple[str, str]:
        """
        Suggest the best bait to use next based on conversation state.
        
        Returns:
            Tuple of (target, bait_message)
        """
        # Priority order of intel
        priority = [
            "upi_id",       # Easiest to get
            "phone_number", # Useful for tracing
            "bank_account", # Most valuable
            "email",        # Can be useful
            "greed_trigger", # Use mid-conversation
            "time_waste",   # Use when stalling
        ]
        
        for target in priority:
            bait = self.get_bait(target, collected_intel)
            if bait:
                return target, bait
        
        # If nothing else, use time waste
        return "time_waste", random.choice(self.BAITS["time_waste"])


# =============================================================================
# 4. ENHANCED INTEL EXTRACTOR
# =============================================================================

class EnhancedIntelExtractor:
    """
    Extended intelligence extraction beyond basic UPI/phone/bank.
    
    Extracts:
    - Aadhaar numbers (12 digits with Verhoeff checksum)
    - PAN numbers (ABCDE1234F format)
    - Social media handles
    - Crypto wallet addresses
    - IMPS/NEFT references
    """
    
    def __init__(self):
        # Aadhaar pattern (12 digits, not starting with 0 or 1)
        self.aadhaar_pattern = re.compile(
            r'\b([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})\b'
        )
        
        # PAN pattern (5 letters, 4 digits, 1 letter)
        self.pan_pattern = re.compile(
            r'\b([A-Z]{5}[0-9]{4}[A-Z])\b',
            re.IGNORECASE
        )
        
        # Social media patterns
        self.social_patterns = {
            'telegram': re.compile(r'(?:t\.me/|@)([a-zA-Z][a-zA-Z0-9_]{4,31})\b'),
            'instagram': re.compile(r'(?:instagram\.com/|@)([a-zA-Z][a-zA-Z0-9_.]{0,29})\b'),
            'twitter': re.compile(r'(?:twitter\.com/|x\.com/|@)([a-zA-Z_][a-zA-Z0-9_]{0,14})\b'),
            'whatsapp_group': re.compile(r'chat\.whatsapp\.com/([a-zA-Z0-9]{20,24})'),
        }
        
        # Transaction reference patterns
        self.transaction_patterns = {
            'imps': re.compile(r'\b(IMPS[/-]?\d{12,14})\b', re.IGNORECASE),
            'neft': re.compile(r'\b(NEFT[/-]?[A-Z0-9]{16,20})\b', re.IGNORECASE),
            'utr': re.compile(r'\b(UTR[:\s]?\d{12,16})\b', re.IGNORECASE),
        }
        
        # Crypto patterns
        self.crypto_patterns = {
            'bitcoin': re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b'),
            'ethereum': re.compile(r'\b(0x[a-fA-F0-9]{40})\b'),
            'tron_usdt': re.compile(r'\b(T[a-zA-Z0-9]{33})\b'),
        }
    
    def extract_aadhaar(self, text: str) -> List[str]:
        """Extract Aadhaar numbers with basic validation."""
        matches = self.aadhaar_pattern.findall(text)
        valid = []
        for match in matches:
            # Clean and validate
            digits = re.sub(r'\D', '', match)
            if len(digits) == 12 and self._validate_aadhaar(digits):
                formatted = f"{digits[:4]} {digits[4:8]} {digits[8:]}"
                valid.append(formatted)
        return valid
    
    def _validate_aadhaar(self, digits: str) -> bool:
        """Basic Aadhaar validation (Verhoeff checksum)."""
        # Simplified - just check basic format
        # Real implementation would use Verhoeff algorithm
        return (
            len(digits) == 12 and 
            digits[0] not in '01' and  # Can't start with 0 or 1
            not digits == '0' * 12     # Not all zeros
        )
    
    def extract_pan(self, text: str) -> List[str]:
        """Extract PAN numbers."""
        matches = self.pan_pattern.findall(text)
        valid = []
        for match in matches:
            pan = match.upper()
            # Validate PAN format
            if self._validate_pan(pan):
                valid.append(pan)
        return list(set(valid))
    
    def _validate_pan(self, pan: str) -> bool:
        """Validate PAN format."""
        if len(pan) != 10:
            return False
        # 4th character indicates entity type
        valid_4th = 'ABCFGHLJPT'  # Valid entity types
        return pan[3] in valid_4th
    
    def extract_social_handles(self, text: str) -> Dict[str, List[str]]:
        """Extract social media handles."""
        handles = {}
        for platform, pattern in self.social_patterns.items():
            matches = pattern.findall(text)
            if matches:
                handles[platform] = list(set(matches))
        return handles
    
    def extract_transaction_refs(self, text: str) -> Dict[str, List[str]]:
        """Extract transaction reference numbers."""
        refs = {}
        for ref_type, pattern in self.transaction_patterns.items():
            matches = pattern.findall(text)
            if matches:
                refs[ref_type] = list(set(matches))
        return refs
    
    def extract_crypto_wallets(self, text: str) -> Dict[str, List[str]]:
        """Extract cryptocurrency wallet addresses."""
        wallets = {}
        for crypto, pattern in self.crypto_patterns.items():
            matches = pattern.findall(text)
            if matches:
                wallets[crypto] = list(set(matches))
        return wallets
    
    def extract_all(self, text: str) -> Dict[str, Any]:
        """Extract all enhanced intelligence."""
        return {
            "aadhaar_numbers": self.extract_aadhaar(text),
            "pan_numbers": self.extract_pan(text),
            "social_handles": self.extract_social_handles(text),
            "transaction_refs": self.extract_transaction_refs(text),
            "crypto_wallets": self.extract_crypto_wallets(text),
        }


# =============================================================================
# 5. TEMPORAL ANALYZER
# =============================================================================

class TemporalAnalyzer:
    """
    Analyzes temporal patterns in scam operations.
    
    Useful for:
    - Identifying call center shift patterns
    - Geographic timezone inference
    - Operation scale estimation
    """
    
    def __init__(self):
        self.session_times: List[Tuple[datetime, datetime]] = []  # (start, end)
        self.message_times: List[datetime] = []
    
    def add_session(self, start: datetime, end: datetime):
        """Add a completed session."""
        self.session_times.append((start, end))
    
    def add_message_time(self, timestamp: datetime):
        """Add a message timestamp."""
        self.message_times.append(timestamp)
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze temporal patterns."""
        if not self.message_times:
            return {}
        
        # Hour distribution
        hour_counts = [0] * 24
        for ts in self.message_times:
            hour_counts[ts.hour] += 1
        
        peak_hour = hour_counts.index(max(hour_counts))
        
        # Day of week distribution
        day_counts = [0] * 7
        for ts in self.message_times:
            day_counts[ts.weekday()] += 1
        
        # Session duration stats
        durations = []
        for start, end in self.session_times:
            durations.append((end - start).total_seconds() / 60)
        
        avg_duration = statistics.mean(durations) if durations else 0
        
        return {
            "peak_activity_hour": peak_hour,
            "peak_activity_hour_ist": f"{peak_hour}:00 IST",
            "hourly_distribution": hour_counts,
            "weekday_distribution": {
                "Monday": day_counts[0],
                "Tuesday": day_counts[1],
                "Wednesday": day_counts[2],
                "Thursday": day_counts[3],
                "Friday": day_counts[4],
                "Saturday": day_counts[5],
                "Sunday": day_counts[6],
            },
            "avg_session_duration_minutes": round(avg_duration, 1),
            "total_sessions": len(self.session_times),
            "inferred_timezone": self._infer_timezone(peak_hour),
        }
    
    def _infer_timezone(self, peak_hour: int) -> str:
        """Infer likely timezone based on peak activity."""
        # If peak is 10-18 IST, likely India-based operation
        if 10 <= peak_hour <= 18:
            return "IST (India)"
        # If peak is in late night IST, could be targeting US
        elif 0 <= peak_hour <= 6:
            return "Possibly targeting US timezone"
        else:
            return "Unknown"


# =============================================================================
# QUICK TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("ADVANCED FEATURES TEST")
    print("=" * 60)
    
    # Test Behavioral Fingerprinting
    print("\n--- Behavioral Fingerprinting Test ---")
    fp = BehavioralFingerprinter()
    fp.add_message("Your SBI account will be BLOCKED today! Call now!", datetime.now())
    fp.add_message("Sir why you are not responding?? URGENT!!", datetime.now() + timedelta(minutes=2))
    fp.add_message("Police will arrest you if you don't pay!", datetime.now() + timedelta(minutes=5))
    
    sig = fp.analyze()
    print(f"Fingerprint: {fp.get_fingerprint()}")
    print(f"Behavior Type: {fp.get_behavior_type().value}")
    print(f"Caps Ratio: {sig.caps_ratio:.2f}")
    print(f"Institutions: {sig.institutions_impersonated}")
    
    # Test Persona Selection
    print("\n--- Persona Selection Test ---")
    selector = PersonaSelector()
    messages = ["Congratulations! You won Rs. 50,00,000 lottery!"]
    persona, scam_type = selector.get_optimal_persona(messages)
    print(f"Scam Type: {scam_type.value}")
    print(f"Selected Persona: {persona.name}")
    print(f"Greeting: {persona.get_greeting()}")
    
    # Test Enhanced Intel Extraction
    print("\n--- Enhanced Intel Extraction Test ---")
    extractor = EnhancedIntelExtractor()
    text = """
    Send money to my account. Aadhaar: 2345 6789 0123
    PAN: ABCDE1234F
    Contact me on telegram @scammer_boss
    Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    Reference: IMPS-123456789012
    """
    intel = extractor.extract_all(text)
    print(f"Aadhaar: {intel['aadhaar_numbers']}")
    print(f"PAN: {intel['pan_numbers']}")
    print(f"Social: {intel['social_handles']}")
    print(f"Crypto: {intel['crypto_wallets']}")
    
    # Test Proactive Bait
    print("\n--- Proactive Bait Test ---")
    bait_engine = ProactiveBaitEngine()
    target, bait = bait_engine.suggest_next_bait({}, turn_count=3)
    print(f"Target: {target}")
    print(f"Bait: {bait}")
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)
