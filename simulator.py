#!/usr/bin/env python3
"""
Simulator: Interactive testing for the honey-pot system
========================================================

This script lets you pretend to be a scammer and interact with the
full honey-pot system. You'll see:
- Real-time scam detection analysis
- Agent persona responses
- Accumulated intelligence
- Session logging

Usage:
    python simulator.py
    
    # Or with a custom session ID:
    python simulator.py --session my_test_session
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyst_engine import AnalystEngine, IncomingPayload, MessageSchema, MetadataSchema, DetectionResult
from agent_brain import AgentBrain, AgentMode
from session_store import SessionStore, Session
from llm_clients import get_analyst_llm, get_agent_llm


# =============================================================================
# SECTION 1: COLORS AND FORMATTING
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def print_header(text: str):
    """Print a header."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text.center(60)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.RESET}\n")


def print_section(title: str):
    """Print a section separator."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- {title} ---{Colors.RESET}")


def print_scammer(text: str):
    """Print scammer message."""
    print(f"{Colors.RED}[SCAMMER] {text}{Colors.RESET}")


def print_agent(text: str, mode: str):
    """Print agent response with mode indicator."""
    mode_color = {
        "NORMAL": Colors.YELLOW,
        "HONEYPOT": Colors.GREEN,
        "END_CONVERSATION": Colors.DIM
    }.get(mode, Colors.RESET)
    print(f"{mode_color}[VIKRAM @{mode}] {text}{Colors.RESET}")


def print_analysis(is_scam: bool, confidence: float, detection: str, reason: str):
    """Print analysis results."""
    status = f"{Colors.RED}🚨 SCAM" if is_scam else f"{Colors.GREEN}✓ SAFE"
    print(f"  {Colors.DIM}Detection:{Colors.RESET} {status}{Colors.RESET} ({confidence:.0%})")
    print(f"  {Colors.DIM}Result:{Colors.RESET} {detection}")
    print(f"  {Colors.DIM}Reason:{Colors.RESET} {reason[:80]}{'...' if len(reason) > 80 else ''}")


def print_intel(intel: dict):
    """Print extracted intelligence."""
    items = []
    for key, values in intel.items():
        if values and key != 'suspicious_keywords':
            items.extend([f"{key}: {v}" for v in values[:3]])
    if items:
        print(f"  {Colors.BOLD}📋 Intel:{Colors.RESET} " + ", ".join(items[:5]))
    else:
        print(f"  {Colors.DIM}📋 Intel: None extracted{Colors.RESET}")


def print_session_summary(session: Session):
    """Print session summary."""
    print_section("SESSION SUMMARY")
    print(f"  Session ID: {session.session_id}")
    print(f"  Total Turns: {session.turn_count}")
    print(f"  Current Mode: {session.current_mode}")
    print(f"  Status: {session.status}")
    
    intel = session.aggregated_intel
    print(f"\n  {Colors.BOLD}COLLECTED INTELLIGENCE:{Colors.RESET}")
    if intel.upi_ids:
        print(f"    UPI IDs: {', '.join(intel.upi_ids)}")
    if intel.phone_numbers:
        print(f"    Phone Numbers: {', '.join(intel.phone_numbers)}")
    if intel.bank_accounts:
        print(f"    Bank Accounts: {', '.join(intel.bank_accounts)}")
    if intel.urls:
        print(f"    URLs: {', '.join(intel.urls[:5])}")
    if intel.emails:
        print(f"    Emails: {', '.join(intel.emails)}")
    if intel.is_empty():
        print(f"    {Colors.DIM}(No intelligence collected yet){Colors.RESET}")


# =============================================================================
# SECTION 2: SIMULATOR CLASS
# =============================================================================

class HoneypotSimulator:
    """
    Interactive simulator for the honey-pot system.
    
    Combines the Analyst Engine and Agent Brain to process
    complete conversation flows with persistence.
    """
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        use_real_llm: bool = True,
        storage_dir: Optional[str] = None
    ):
        """
        Initialize the simulator.
        
        Args:
            session_id: Session ID (auto-generated if not provided).
            use_real_llm: Whether to use real LLM (requires API key).
            storage_dir: Directory for session storage (default: ./sessions relative to this file).
        """
        # Generate session ID if not provided
        self.session_id = session_id or f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Use absolute path for storage directory (relative to this script's location)
        if storage_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            storage_dir = os.path.join(script_dir, "sessions")
        
        # Initialize storage
        self.store = SessionStore(storage_dir)
        self.session = self.store.get_or_create(
            self.session_id,
            {"simulator": True, "started": datetime.now().isoformat()}
        )
        
        # Initialize LLM clients
        force_mock = not use_real_llm
        try:
            analyst_llm = get_analyst_llm(force_mock=force_mock)
            agent_llm = get_agent_llm(force_mock=force_mock)
        except Exception as e:
            print(f"{Colors.YELLOW}Warning: {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}Falling back to mock LLMs{Colors.RESET}")
            analyst_llm = get_analyst_llm(force_mock=True)
            agent_llm = get_agent_llm(force_mock=True)
        
        # Initialize engines
        self.analyst = AnalystEngine(llm=analyst_llm)
        self.brain = AgentBrain(llm_client=agent_llm)
        
        # Track current mode
        self.current_mode: Optional[AgentMode] = None
        if self.session.current_mode and self.session.current_mode != "NORMAL":
            try:
                self.current_mode = AgentMode[self.session.current_mode]
            except KeyError:
                pass
    
    def process_message(self, scammer_message: str) -> dict:
        """
        Process a single message from the "scammer".
        
        Args:
            scammer_message: The message to process.
            
        Returns:
            Dictionary with analysis and response.
        """
        # Build payload for analyst
        payload = IncomingPayload(
            sessionId=self.session_id,
            message=MessageSchema(
                text=scammer_message,
                sender="scammer",
                timestamp=datetime.now().isoformat()
            ),
            conversationHistory=[
                MessageSchema(text=t.scammer_message, sender="scammer", timestamp=t.timestamp)
                for t in self.session.turns
            ],
            metadata=MetadataSchema(channel="simulator", language="en-IN", locale="IN")
        )
        
        # Run analyst
        analysis = self.analyst.analyze_session(payload)
        
        # Extract intel dict
        intel_dict = {
            "upi_ids": analysis.extracted_data.upi_ids,
            "phone_numbers": analysis.extracted_data.phone_numbers,
            "bank_accounts": analysis.extracted_data.bank_accounts,
            "urls": analysis.extracted_data.urls,
            "suspicious_keywords": analysis.extracted_data.suspicious_keywords
        }
        
        # Get detection result string
        detection_str = analysis.detection_result.value if hasattr(analysis.detection_result, 'value') else str(analysis.detection_result)
        
        # Run agent brain
        response, new_mode = self.brain.process_turn(
            user_message=scammer_message,
            history=self.session.get_history(),
            extracted_intel=intel_dict,
            detection_result=detection_str,
            current_mode=self.current_mode
        )
        
        # Update current mode
        self.current_mode = new_mode
        mode_str = new_mode.value.upper() if hasattr(new_mode, 'value') else str(new_mode)
        
        # Add turn to session
        self.session.add_turn(
            scammer_message=scammer_message,
            agent_response=response,
            is_scam=analysis.is_scam,
            confidence=analysis.confidence_score,
            detection_result=detection_str,
            agent_mode=mode_str,
            intel=intel_dict
        )
        
        # Save session
        self.store.save(self.session)
        
        return {
            "response": response,
            "mode": mode_str,
            "is_scam": analysis.is_scam,
            "confidence": analysis.confidence_score,
            "detection_result": detection_str,
            "reason": analysis.reason,
            "intel": intel_dict
        }
    
    def run_interactive(self):
        """Run the interactive simulator loop."""
        print_header("HONEYPOT SIMULATOR")
        print(f"Session: {Colors.CYAN}{self.session_id}{Colors.RESET}")
        print(f"Storage: {Colors.DIM}{self.store.storage_dir}{Colors.RESET}")
        print(f"\nYou are the SCAMMER. Try to scam 'Vikram Singh'.")
        print(f"Commands: {Colors.DIM}/summary, /intel, /quit, /help{Colors.RESET}\n")
        
        # Show existing turns if resuming
        if self.session.turn_count > 0:
            print(f"{Colors.YELLOW}Resuming session with {self.session.turn_count} existing turns{Colors.RESET}")
            print(f"Current mode: {self.session.current_mode}\n")
        
        while True:
            try:
                # Get input
                user_input = input(f"{Colors.RED}[You (Scammer)]> {Colors.RESET}").strip()
                
                if not user_input:
                    continue
                
                # Handle commands
                if user_input.startswith('/'):
                    cmd = user_input.lower()
                    if cmd == '/quit' or cmd == '/exit':
                        print_session_summary(self.session)
                        print(f"\n{Colors.DIM}Session saved to: {self.store._get_path(self.session_id)}{Colors.RESET}")
                        break
                    elif cmd == '/summary':
                        print_session_summary(self.session)
                        continue
                    elif cmd == '/intel':
                        print_section("ACCUMULATED INTELLIGENCE")
                        intel = self.session.aggregated_intel
                        print(f"  {intel.summary()}")
                        for key in ['upi_ids', 'phone_numbers', 'bank_accounts', 'urls', 'emails']:
                            values = getattr(intel, key, [])
                            if values:
                                print(f"  {key}: {values}")
                        continue
                    elif cmd == '/history':
                        print_section("CONVERSATION HISTORY")
                        for turn in self.session.turns[-5:]:
                            print(f"  [{turn.turn_number}] SCAMMER: {turn.scammer_message[:50]}...")
                            print(f"      VIKRAM: {turn.agent_response[:50]}...")
                        continue
                    elif cmd == '/help':
                        print(f"\n{Colors.CYAN}Commands:{Colors.RESET}")
                        print("  /summary  - Show session summary")
                        print("  /intel    - Show collected intelligence")
                        print("  /history  - Show last 5 turns")
                        print("  /quit     - End simulation")
                        continue
                    else:
                        print(f"{Colors.DIM}Unknown command. Try /help{Colors.RESET}")
                        continue
                
                # Process message
                result = self.process_message(user_input)
                
                # Display results
                print_section(f"ANALYSIS (Turn {self.session.turn_count})")
                print_analysis(
                    result["is_scam"],
                    result["confidence"],
                    result["detection_result"],
                    result["reason"]
                )
                print_intel(result["intel"])
                
                print_section("RESPONSE")
                print_agent(result["response"], result["mode"])
                
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Interrupted. Type /quit to exit properly.{Colors.RESET}")
            except EOFError:
                break
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                import traceback
                traceback.print_exc()


# =============================================================================
# SECTION 3: MAIN
# =============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Interactive honeypot system simulator"
    )
    parser.add_argument(
        "--session", "-s",
        type=str,
        default=None,
        help="Session ID (auto-generated if not provided)"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock LLMs instead of real API calls"
    )
    parser.add_argument(
        "--storage", "-d",
        type=str,
        default="./sessions",
        help="Directory for session storage"
    )
    
    args = parser.parse_args()
    
    # Create and run simulator
    sim = HoneypotSimulator(
        session_id=args.session,
        use_real_llm=not args.mock,
        storage_dir=args.storage
    )
    sim.run_interactive()


if __name__ == "__main__":
    main()
