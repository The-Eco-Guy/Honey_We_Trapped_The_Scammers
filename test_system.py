#!/usr/bin/env python3
"""
Quick system test script for the Honey-Pot system.
Run with: python test_system.py
         python test_system.py --real  (to use real LLM API)
"""

import sys
import warnings
import argparse

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Add current directory to path
sys.path.insert(0, '.')

from analyst_engine import AnalystEngine, IncomingPayload, MessageSchema
from agent_brain import AgentBrain, AgentMode
from session_store import SessionStore
from llm_clients import get_analyst_llm, get_agent_llm

def main():
    parser = argparse.ArgumentParser(description="Test the Honey-Pot system")
    parser.add_argument("--real", action="store_true", help="Use real LLM API instead of mock")
    args = parser.parse_args()
    
    use_mock = not args.real
    
    print("=" * 60)
    print("HONEY-POT SYSTEM - INTEGRATION TEST")
    print("=" * 60)
    
    mode_str = "MOCK" if use_mock else "REAL API"
    print(f"\n[1/4] Initializing LLM clients ({mode_str} mode)...")
    try:
        analyst_llm = get_analyst_llm(force_mock=use_mock)
        agent_llm = get_agent_llm(force_mock=use_mock)
    except Exception as e:
        print(f"Failed to init LLM: {e}")
        print("Falling back to mock mode...")
        analyst_llm = get_analyst_llm(force_mock=True)
        agent_llm = get_agent_llm(force_mock=True)
    print("✅ LLM clients initialized")
    
    print("\n[2/4] Initializing Analyst Engine...")
    analyst = AnalystEngine(llm=analyst_llm)
    print("✅ Analyst Engine initialized")
    
    print("\n[3/4] Initializing Agent Brain...")
    brain = AgentBrain(llm_client=agent_llm)
    print("✅ Agent Brain initialized")
    
    print("\n[4/4] Testing Session Store...")
    store = SessionStore("./test_sessions")
    session = store.create("integration_test", {"test": True})
    print(f"✅ Session created: {session.session_id}")
    
    print("\n" + "=" * 60)
    print("RUNNING SCAM DETECTION TEST")
    print("=" * 60)
    
    # Test payload - typical scam message
    test_message = "URGENT! Your SBI account will be BLOCKED today! Send OTP to 9876543210 or transfer to scammer@ybl immediately!"
    
    payload = IncomingPayload(
        sessionId='test_integration',
        message=MessageSchema(
            text=test_message,
            sender='scammer',
            timestamp='2026-01-30T10:00:00Z'
        ),
        conversationHistory=[]
    )
    
    print(f"\n📨 Input Message:")
    print(f"   {test_message}\n")
    
    # Run analysis
    result = analyst.analyze_session(payload)
    
    print("📊 Analysis Results:")
    print(f"   is_scam: {result.is_scam}")
    print(f"   confidence: {result.confidence_score:.2%}")
    print(f"   detection_result: {result.detection_result.value}")
    print(f"   risk_category: {result.risk_category}")
    
    print("\n📋 Extracted Intelligence:")
    print(f"   UPI IDs: {result.extracted_data.upi_ids}")
    print(f"   Phone Numbers: {result.extracted_data.phone_numbers}")
    print(f"   Bank Accounts: {result.extracted_data.bank_accounts}")
    print(f"   URLs: {result.extracted_data.urls}")
    print(f"   Keywords: {result.extracted_data.suspicious_keywords[:5]}...")
    
    # Run agent brain
    print("\n" + "=" * 60)
    print("TESTING AGENT RESPONSE GENERATION")
    print("=" * 60)
    
    intel_dict = {
        "upi_ids": result.extracted_data.upi_ids,
        "phone_numbers": result.extracted_data.phone_numbers,
        "bank_accounts": result.extracted_data.bank_accounts,
    }
    
    response, mode = brain.process_turn(
        user_message=test_message,
        history=[],
        extracted_intel=intel_dict,
        detection_result=result.detection_result.value,
        current_mode=None
    )
    
    print(f"\n🤖 Agent Mode: {mode.value}")
    print(f"\n💬 Response (as Ramesh Gupta):")
    print(f"   {response}")
    
    # Cleanup
    store.delete("integration_test")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    tests_passed = 0
    
    # Check detection
    if result.is_scam:
        print("✅ Scam detection: PASSED")
        tests_passed += 1
    else:
        print("❌ Scam detection: FAILED")
    
    # Check intelligence extraction
    if result.extracted_data.upi_ids or result.extracted_data.phone_numbers:
        print("✅ Intelligence extraction: PASSED")
        tests_passed += 1
    else:
        print("❌ Intelligence extraction: FAILED")
    
    # Check response generation
    if response and len(response) > 10:
        print("✅ Response generation: PASSED")
        tests_passed += 1
    else:
        print("❌ Response generation: FAILED")
    
    # Check mode determination
    if mode in [AgentMode.HONEYPOT, AgentMode.NORMAL]:
        print("✅ Mode determination: PASSED")
        tests_passed += 1
    else:
        print("❌ Mode determination: FAILED")
    
    print(f"\n📊 Tests Passed: {tests_passed}/4")
    print("=" * 60)
    
    if tests_passed == 4:
        print("🎉 ALL TESTS PASSED! System is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
