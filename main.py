"""
main.py - FastAPI Honeypot API
==============================

This is the main API endpoint for the Agentic Honeypot System.
Deploy this to receive scam messages, engage scammers, and report intelligence.

Usage:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Endpoints:
    POST /api/message          - Process incoming scammer message
    GET  /api/session/{id}     - Get session details
    GET  /api/health           - Health check
    POST /api/admin/callback   - Manually trigger GUVI callback (testing)
"""

from __future__ import annotations

import os
import time
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import your existing modules
from analyst_engine import (
    AnalystEngine, 
    IncomingPayload, 
    MessageSchema, 
    MetadataSchema,
    DetectionResult
)
from agent_brain import AgentBrain, AgentMode
from session_store import SessionStore
from llm_clients import get_analyst_llm, get_agent_llm

# =============================================================================
# CONFIGURATION
# =============================================================================

# API Key for authentication (set via environment variable in production)
API_KEY = os.getenv("HONEYPOT_API_KEY", "your_secret_api_key_here")

# GUVI Callback URL
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Conversation limits
MAX_TURNS_BEFORE_CALLBACK = 15  # After this many turns, trigger callback
MIN_INTEL_FOR_CALLBACK = 1      # Minimum intel items before callback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("HoneypotAPI")

# =============================================================================
# FASTAPI APP INITIALIZATION
# =============================================================================

app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered scam detection and engagement system",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# GLOBAL INSTANCES (initialized on startup)
# =============================================================================

store: Optional[SessionStore] = None
analyst: Optional[AnalystEngine] = None
brain: Optional[AgentBrain] = None


@app.on_event("startup")
async def startup_event():
    """Initialize all components on server startup."""
    global store, analyst, brain
    
    logger.info("Initializing Honeypot API components...")
    
    # Initialize session store
    store = SessionStore("./sessions")
    logger.info(f"Session store initialized at: {store.storage_dir}")
    
    # Initialize LLM clients (with fallback to mock if no API key)
    try:
        analyst_llm = get_analyst_llm(force_mock=False)
        agent_llm = get_agent_llm(force_mock=False)
        logger.info("Real LLM clients initialized")
    except Exception as e:
        logger.warning(f"Failed to init real LLM: {e}. Using mock.")
        analyst_llm = get_analyst_llm(force_mock=True)
        agent_llm = get_agent_llm(force_mock=True)
    
    # Initialize engines
    analyst = AnalystEngine(llm=analyst_llm)
    brain = AgentBrain(llm_client=agent_llm)
    
    logger.info("Honeypot API ready to receive messages!")


# =============================================================================
# PYDANTIC MODELS FOR API
# =============================================================================

class MessageRequest(BaseModel):
    """Request model matching GUVI's expected format."""
    sessionId: str = Field(..., description="Unique session identifier")
    message: Dict[str, Any] = Field(..., description="Message object with text, sender, timestamp")
    conversationHistory: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = Field(default=None)


class MessageResponse(BaseModel):
    """Response model as per GUVI requirements."""
    status: str = "success"
    reply: str


class SessionResponse(BaseModel):
    """Response model for session details."""
    session_id: str
    turn_count: int
    current_mode: str
    status: str
    intel_summary: str
    created_at: str
    updated_at: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: str
    components: Dict[str, str]


# =============================================================================
# GUVI CALLBACK FUNCTION
# =============================================================================

def send_guvi_callback(session, agent_notes: str = None) -> bool:
    """
    Send final intelligence to GUVI endpoint.
    
    This is MANDATORY for evaluation scoring.
    
    Args:
        session: The Session object with aggregated intelligence.
        agent_notes: Optional notes about the engagement.
        
    Returns:
        True if callback was successful, False otherwise.
    """
    intel = session.aggregated_intel
    
    # Build payload as per GUVI specification
    payload = {
        "sessionId": session.session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session.turn_count * 2,  # Both scammer and agent messages
        "extractedIntelligence": {
            "bankAccounts": intel.bank_accounts[:10],  # Limit to 10
            "upiIds": intel.upi_ids[:10],
            "phishingLinks": intel.urls[:10],
            "phoneNumbers": intel.phone_numbers[:10],
            "suspiciousKeywords": intel.suspicious_keywords[:20]
        },
        "agentNotes": agent_notes or generate_agent_notes(session)
    }
    
    logger.info(f"Sending GUVI callback for session: {session.session_id}")
    logger.info(f"Payload: {payload}")
    
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            logger.info(f"GUVI callback successful: {response.text}")
            return True
        else:
            logger.error(f"GUVI callback failed: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        logger.error("GUVI callback timed out")
        return False
    except Exception as e:
        logger.error(f"GUVI callback error: {e}")
        return False


def generate_agent_notes(session) -> str:
    """Generate descriptive notes about the engagement."""
    notes_parts = []
    
    # Engagement duration
    notes_parts.append(f"Engaged for {session.turn_count} turns")
    
    # Intel summary
    intel = session.aggregated_intel
    if intel.upi_ids:
        notes_parts.append(f"Extracted {len(intel.upi_ids)} UPI ID(s)")
    if intel.phone_numbers:
        notes_parts.append(f"Extracted {len(intel.phone_numbers)} phone number(s)")
    if intel.bank_accounts:
        notes_parts.append(f"Extracted {len(intel.bank_accounts)} bank account(s)")
    
    # Scam type inference
    keywords = [kw.lower() for kw in intel.suspicious_keywords]
    if any(kw in keywords for kw in ['kyc', 'verify', 'block']):
        notes_parts.append("Scam type: KYC/Account blocking fraud")
    elif any(kw in keywords for kw in ['lottery', 'prize', 'winner']):
        notes_parts.append("Scam type: Lottery/Prize scam")
    elif any(kw in keywords for kw in ['refund', 'cashback']):
        notes_parts.append("Scam type: Refund fraud")
    elif any(kw in keywords for kw in ['police', 'arrest', 'court']):
        notes_parts.append("Scam type: Authority impersonation")
    
    return ". ".join(notes_parts)


def should_trigger_callback(session) -> bool:
    """
    Determine if we should send the GUVI callback.
    
    Conditions:
    1. Scam was confirmed (session has intel)
    2. Engagement has reached sufficient depth OR scammer disengaged
    3. Minimum intel has been extracted
    """
    intel = session.aggregated_intel
    
    # Count total intel items
    total_intel = (
        len(intel.upi_ids) + 
        len(intel.phone_numbers) + 
        len(intel.bank_accounts) + 
        len(intel.urls)
    )
    
    # Trigger conditions
    conditions = [
        session.turn_count >= MAX_TURNS_BEFORE_CALLBACK,  # Max turns reached
        session.current_mode == "END_CONVERSATION",        # Agent ended
        session.status == "flagged",                       # Manually flagged
    ]
    
    # At least one condition must be true AND we need minimum intel
    return any(conditions) and total_intel >= MIN_INTEL_FOR_CALLBACK


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        components={
            "session_store": "ok" if store else "not initialized",
            "analyst_engine": "ok" if analyst else "not initialized",
            "agent_brain": "ok" if brain else "not initialized"
        }
    )


@app.post("/api/message", response_model=MessageResponse)
async def process_message(
    request: MessageRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Main endpoint to process incoming scammer messages.
    
    This endpoint:
    1. Validates the API key
    2. Analyzes the message for scam intent
    3. Generates an engaging response
    4. Extracts intelligence
    5. Triggers GUVI callback when appropriate
    """
    # Validate API key
    if x_api_key != API_KEY:
        logger.warning(f"Invalid API key attempt: {x_api_key[:8]}...")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    start_time = time.time()
    
    try:
        # Parse incoming payload into Pydantic model
        incoming = IncomingPayload(
            sessionId=request.sessionId,
            message=MessageSchema(
                text=request.message.get("text", ""),
                sender=request.message.get("sender", "scammer"),
                timestamp=request.message.get("timestamp", datetime.now().isoformat())
            ),
            conversationHistory=[
                MessageSchema(
                    text=msg.get("text", ""),
                    sender=msg.get("sender", "unknown"),
                    timestamp=msg.get("timestamp", "")
                )
                for msg in request.conversationHistory
            ],
            metadata=MetadataSchema(**request.metadata) if request.metadata else MetadataSchema()
        )
        
        session_id = incoming.sessionId
        logger.info(f"Processing message for session: {session_id}")
        
        # Get or create session
        session = store.get_or_create(session_id, {
            "source": "api",
            "channel": incoming.metadata.channel,
            "started": datetime.now().isoformat()
        })
        
        # Run analyst engine
        analysis = analyst.analyze_session(incoming)
        
        logger.info(f"Analysis result: is_scam={analysis.is_scam}, confidence={analysis.confidence_score:.2f}")
        
        # Determine current mode
        if session.current_mode and session.current_mode != "NORMAL":
            try:
                current_mode = AgentMode[session.current_mode]
            except KeyError:
                current_mode = None
        else:
            current_mode = None
        
        # Build intel dict for agent brain
        intel_dict = {
            "upi_ids": analysis.extracted_data.upi_ids,
            "phone_numbers": analysis.extracted_data.phone_numbers,
            "bank_accounts": analysis.extracted_data.bank_accounts,
            "urls": analysis.extracted_data.urls,
            "suspicious_keywords": analysis.extracted_data.suspicious_keywords
        }
        
        # Get detection result string
        detection_str = analysis.detection_result.value if hasattr(analysis.detection_result, 'value') else str(analysis.detection_result)
        
        # Generate agent response
        response, new_mode = brain.process_turn(
            user_message=incoming.message.text,
            history=session.get_history(),
            extracted_intel=intel_dict,
            detection_result=detection_str,
            current_mode=current_mode
        )
        
        # Get mode string
        mode_str = new_mode.value.upper() if hasattr(new_mode, 'value') else str(new_mode)
        
        # Add turn to session
        session.add_turn(
            scammer_message=incoming.message.text,
            agent_response=response,
            is_scam=analysis.is_scam,
            confidence=analysis.confidence_score,
            detection_result=detection_str,
            agent_mode=mode_str,
            intel=intel_dict
        )
        
        # Save session
        store.save(session)
        
        # Check if we should trigger GUVI callback
        if should_trigger_callback(session):
            # Run callback in background to not block response
            background_tasks.add_task(send_guvi_callback, session)
            logger.info(f"GUVI callback scheduled for session: {session_id}")
        
        # Calculate processing time
        processing_time = time.time() - start_time
        logger.info(f"Response generated in {processing_time:.2f}s: {response[:50]}...")
        
        return MessageResponse(
            status="success",
            reply=response
        )
        
    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/session/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Get details of a specific session."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return SessionResponse(
        session_id=session.session_id,
        turn_count=session.turn_count,
        current_mode=session.current_mode,
        status=session.status,
        intel_summary=session.aggregated_intel.summary(),
        created_at=session.created_at,
        updated_at=session.updated_at
    )


@app.get("/api/sessions")
async def list_sessions(
    x_api_key: str = Header(..., alias="x-api-key"),
    limit: int = 20
):
    """List recent sessions."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session_ids = store.list_sessions()[-limit:]
    sessions = []
    
    for sid in session_ids:
        session = store.get(sid)
        if session:
            sessions.append({
                "session_id": session.session_id,
                "turn_count": session.turn_count,
                "current_mode": session.current_mode,
                "intel_summary": session.aggregated_intel.summary(),
                "updated_at": session.updated_at
            })
    
    return {"sessions": sessions, "total": len(session_ids)}


@app.post("/api/admin/callback/{session_id}")
async def trigger_callback(
    session_id: str,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Manually trigger GUVI callback for testing."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session = store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    success = send_guvi_callback(session)
    
    return {
        "session_id": session_id,
        "callback_sent": success,
        "intel_summary": session.aggregated_intel.summary()
    }


@app.get("/api/stats")
async def get_stats(
    x_api_key: str = Header(..., alias="x-api-key")
):
    """Get system statistics."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return store.get_stats()


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   HONEYPOT API SERVER                        ║
╠══════════════════════════════════════════════════════════════╣
║  Starting on: http://{host}:{port}                           
║  Docs:        http://{host}:{port}/docs                      
║  API Key:     {API_KEY[:8]}...                               
╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
    )
