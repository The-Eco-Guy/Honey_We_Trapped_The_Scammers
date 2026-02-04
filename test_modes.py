#!/usr/bin/env python3
"""Test both NORMAL and HONEYPOT modes with real LLM."""

from agent_brain import AgentBrain, AgentMode
from analyst_engine import AnalystEngine
from llm_clients import get_analyst_llm, get_agent_llm

print('='*60)
print('TEST 1: NORMAL MODE (non-scam casual conversation)')
print('='*60)

# Initialize with real LLM
agent_llm = get_agent_llm(force_mock=False)
analyst_llm = get_analyst_llm(force_mock=False)

brain = AgentBrain(llm_client=agent_llm)
analyst = AnalystEngine(llm=analyst_llm)

# Test casual conversation
messages = [
    'Hi, how was your football game today?',
    "i'm the guy you met at the stadium, remember me?",
    "nothing don't worry. sorry for bothering you",
]

history = []
for i, msg in enumerate(messages, 1):
    print(f'\n[{i}] User: {msg}')
    
    response, mode = brain.process_turn(
        user_message=msg,
        history=history,
        detection_result='inconclusive',  # Not a scam
        current_mode=AgentMode.NORMAL if i > 1 else None
    )
    print(f'    Ramesh [{mode.value}]: {response}')
    
    history.append({'sender': 'user', 'text': msg})
    history.append({'sender': 'agent', 'text': response})

print()
print('='*60)
print('TEST 2: HONEYPOT MODE (scam - intel extraction)')
print('='*60)

brain2 = AgentBrain(llm_client=agent_llm)

# Test scam scenario
messages2 = [
    'URGENT! Your account is blocked. Send money to 9876543210 now!',
    'Hurry up! Send 10000 to my UPI shreyas@paytm',
    'Did you send the money?? BE QUICK!',
    'Ok I will give you my bank account: 12345678901 HDFC IFSC: HDFC0001234',
]

intel = {'upi_ids': ['shreyas@paytm'], 'phone_numbers': ['+919876543210'], 'bank_accounts': []}
history2 = []
current_mode = None

for i, msg in enumerate(messages2, 1):
    print(f'\n[{i}] Scammer: {msg}')
    
    response, new_mode = brain2.process_turn(
        user_message=msg,
        history=history2,
        extracted_intel=intel,
        detection_result='scam_confirmed',
        current_mode=current_mode
    )
    print(f'    Ramesh [{new_mode.value}]: {response}')
    
    history2.append({'sender': 'user', 'text': msg})
    history2.append({'sender': 'agent', 'text': response})
    current_mode = new_mode
    
    # Update intel
    if '12345678901' in msg:
        intel['bank_accounts'].append('12345678901')

print()
print('Done!')
