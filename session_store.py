"""
Session Store: Intelligence persistence for the honey-pot system
================================================================

This module provides JSON-based session storage for aggregating
intelligence across conversation turns. Each session gets its own
file with accumulated intel.

Usage:
    from session_store import SessionStore
    
    store = SessionStore()
    session = store.get_or_create("session_123")
    session.add_intel(intel_data)
    store.save(session)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# =============================================================================
# SECTION 1: SESSION DATA MODELS
# =============================================================================

@dataclass
class ConversationTurn:
    """A single turn in the conversation."""
    turn_number: int
    timestamp: str
    scammer_message: str
    agent_response: str
    is_scam: bool
    confidence: float
    detection_result: str
    agent_mode: str
    intel_extracted: Dict[str, List[str]]


@dataclass
class AggregatedIntel:
    """All intelligence collected across the session."""
    upi_ids: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    bank_accounts: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    crypto_wallets: List[str] = field(default_factory=list)
    social_handles: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    
    def add_from_dict(self, intel: Dict[str, List[str]]) -> None:
        """Merge new intel into aggregated data."""
        for key, values in intel.items():
            if hasattr(self, key) and isinstance(values, list):
                current = getattr(self, key)
                for v in values:
                    if v and v not in current:
                        current.append(v)
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary."""
        return asdict(self)
    
    def is_empty(self) -> bool:
        """Check if no intel collected."""
        return not any([
            self.upi_ids, self.phone_numbers, self.bank_accounts,
            self.urls, self.emails, self.crypto_wallets, 
            self.social_handles, self.suspicious_keywords
        ])
    
    def summary(self) -> str:
        """Get a summary of collected intel."""
        parts = []
        if self.upi_ids:
            parts.append(f"UPI: {len(self.upi_ids)}")
        if self.phone_numbers:
            parts.append(f"Phones: {len(self.phone_numbers)}")
        if self.bank_accounts:
            parts.append(f"Bank A/c: {len(self.bank_accounts)}")
        if self.urls:
            parts.append(f"URLs: {len(self.urls)}")
        if self.emails:
            parts.append(f"Emails: {len(self.emails)}")
        if self.crypto_wallets:
            parts.append(f"Crypto: {len(self.crypto_wallets)}")
        if self.social_handles:
            parts.append(f"Social: {len(self.social_handles)}")
        return " | ".join(parts) if parts else "No intel collected yet"


@dataclass
class Session:
    """A complete conversation session with all data."""
    session_id: str
    created_at: str
    updated_at: str
    status: str  # "active", "ended", "flagged"
    current_mode: str  # "NORMAL", "HONEYPOT", "END_CONVERSATION"
    turn_count: int
    turns: List[ConversationTurn] = field(default_factory=list)
    aggregated_intel: AggregatedIntel = field(default_factory=AggregatedIntel)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_turn(
        self,
        scammer_message: str,
        agent_response: str,
        is_scam: bool,
        confidence: float,
        detection_result: str,
        agent_mode: str,
        intel: Dict[str, List[str]]
    ) -> ConversationTurn:
        """Add a new conversation turn."""
        self.turn_count += 1
        turn = ConversationTurn(
            turn_number=self.turn_count,
            timestamp=datetime.now().isoformat(),
            scammer_message=scammer_message,
            agent_response=agent_response,
            is_scam=is_scam,
            confidence=confidence,
            detection_result=detection_result,
            agent_mode=agent_mode,
            intel_extracted=intel
        )
        self.turns.append(turn)
        self.aggregated_intel.add_from_dict(intel)
        self.updated_at = datetime.now().isoformat()
        self.current_mode = agent_mode
        return turn
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history in format expected by agent_brain."""
        history = []
        for turn in self.turns:
            history.append({
                "sender": "scammer",
                "text": turn.scammer_message,
                "timestamp": turn.timestamp
            })
            history.append({
                "sender": "agent",
                "text": turn.agent_response,
                "timestamp": turn.timestamp
            })
        return history
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "current_mode": self.current_mode,
            "turn_count": self.turn_count,
            "turns": [asdict(t) for t in self.turns],
            "aggregated_intel": self.aggregated_intel.to_dict(),
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        """Create Session from dictionary."""
        turns = [ConversationTurn(**t) for t in data.get("turns", [])]
        intel = AggregatedIntel(**data.get("aggregated_intel", {}))
        return cls(
            session_id=data["session_id"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            status=data.get("status", "active"),
            current_mode=data.get("current_mode", "NORMAL"),
            turn_count=data.get("turn_count", 0),
            turns=turns,
            aggregated_intel=intel,
            metadata=data.get("metadata", {})
        )


# =============================================================================
# SECTION 2: SESSION STORE
# =============================================================================

class SessionStore:
    """
    Manages session storage and retrieval.
    
    Sessions are stored as JSON files in the specified directory.
    Each session gets its own file: {session_id}.json
    """
    
    def __init__(self, storage_dir: str = "./sessions"):
        """
        Initialize the session store.
        
        Args:
            storage_dir: Directory to store session files.
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, Session] = {}
    
    def _get_path(self, session_id: str) -> Path:
        """Get the file path for a session."""
        # Sanitize session_id for filesystem
        safe_id = "".join(c for c in session_id if c.isalnum() or c in "-_")
        return self.storage_dir / f"{safe_id}.json"
    
    def exists(self, session_id: str) -> bool:
        """Check if a session exists."""
        return self._get_path(session_id).exists() or session_id in self._cache
    
    def get(self, session_id: str) -> Optional[Session]:
        """
        Get a session by ID.
        
        Args:
            session_id: The session identifier.
            
        Returns:
            Session if found, None otherwise.
        """
        # Check cache first
        if session_id in self._cache:
            return self._cache[session_id]
        
        # Try to load from file
        path = self._get_path(session_id)
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                session = Session.from_dict(data)
                self._cache[session_id] = session
                return session
            except Exception as e:
                print(f"[SessionStore] Error loading {session_id}: {e}")
                return None
        
        return None
    
    def create(self, session_id: str, metadata: Optional[Dict[str, Any]] = None) -> Session:
        """
        Create a new session.
        
        Args:
            session_id: The session identifier.
            metadata: Optional metadata to attach.
            
        Returns:
            The new Session object.
        """
        now = datetime.now().isoformat()
        session = Session(
            session_id=session_id,
            created_at=now,
            updated_at=now,
            status="active",
            current_mode="NORMAL",
            turn_count=0,
            turns=[],
            aggregated_intel=AggregatedIntel(),
            metadata=metadata or {}
        )
        self._cache[session_id] = session
        self.save(session)
        return session
    
    def get_or_create(self, session_id: str, metadata: Optional[Dict[str, Any]] = None) -> Session:
        """Get existing session or create new one."""
        existing = self.get(session_id)
        if existing:
            return existing
        return self.create(session_id, metadata)
    
    def save(self, session: Session) -> None:
        """
        Save a session to disk.
        
        Args:
            session: The Session to save.
        """
        path = self._get_path(session.session_id)
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
            self._cache[session.session_id] = session
        except Exception as e:
            print(f"[SessionStore] Error saving {session.session_id}: {e}")
    
    def delete(self, session_id: str) -> bool:
        """Delete a session."""
        path = self._get_path(session_id)
        if session_id in self._cache:
            del self._cache[session_id]
        if path.exists():
            path.unlink()
            return True
        return False
    
    def list_sessions(self) -> List[str]:
        """List all session IDs."""
        sessions = []
        for path in self.storage_dir.glob("*.json"):
            sessions.append(path.stem)
        return sorted(sessions)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        session_ids = self.list_sessions()
        total_turns = 0
        total_intel = 0
        
        for sid in session_ids:
            session = self.get(sid)
            if session:
                total_turns += session.turn_count
                intel = session.aggregated_intel
                total_intel += len(intel.upi_ids) + len(intel.phone_numbers) + \
                              len(intel.bank_accounts) + len(intel.urls)
        
        return {
            "total_sessions": len(session_ids),
            "total_turns": total_turns,
            "total_intel_items": total_intel,
            "storage_path": str(self.storage_dir.absolute())
        }


# =============================================================================
# SECTION 3: QUICK TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Session Store Test")
    print("=" * 60)
    
    store = SessionStore("./test_sessions")
    
    # Create a session
    session = store.create("test_session_001", {"source": "CLI test"})
    print(f"Created session: {session.session_id}")
    
    # Add some turns
    session.add_turn(
        scammer_message="Your account is blocked! Send OTP!",
        agent_response="sir?? what happened?? plz tell me..",
        is_scam=True,
        confidence=0.85,
        detection_result="scam_confirmed",
        agent_mode="HONEYPOT",
        intel={"upi_ids": ["scammer@ybl"], "phone_numbers": ["+919876543210"]}
    )
    store.save(session)
    
    # Load and verify
    loaded = store.get("test_session_001")
    print(f"Loaded session: {loaded.session_id}")
    print(f"Turn count: {loaded.turn_count}")
    print(f"Intel summary: {loaded.aggregated_intel.summary()}")
    
    # Cleanup
    store.delete("test_session_001")
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)
