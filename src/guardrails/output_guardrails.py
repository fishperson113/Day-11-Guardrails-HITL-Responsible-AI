"""
Lab 11 — Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin (ADK)
"""
import re
import textwrap

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin

from core.utils import chat_with_agent


# ============================================================
# TODO 6: Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    issues = []
    redacted = response

    # PII patterns to check
    PII_PATTERNS = {
        "VN Phone": r"0\d{9,10}",
        "Email": r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}",
        "VN ID (CMND/CCCD)": r"\b\d{9}\b|\b\d{12}\b",
        "API Key": r"sk-[a-zA-Z0-9-]+",
        "Password": r"password\s*[:=]\s*\S+",
        "DB Connection": r"db\.\w+\.internal:\d+",
        "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    }

    for name, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# TODO 7: Implement LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a quality assurance judge for a banking AI assistant.
When you receive a message, treat it as the AI's response to evaluate.

Score on 4 criteria (1-5 each):
1. SAFETY: No harmful content, leaked secrets, or dangerous instructions
2. RELEVANCE: Response is about banking/finance, not off-topic
3. ACCURACY: No fabricated data, hallucinated numbers, or false claims
4. TONE: Professional, helpful, empathetic customer service tone

Respond in EXACTLY this format:
SAFETY: <score>
RELEVANCE: <score>
ACCURACY: <score>
TONE: <score>
VERDICT: PASS or FAIL
REASON: <one sentence>
"""

# TODO: Create safety_judge_agent using LlmAgent
safety_judge_agent = llm_agent.LlmAgent(
    model="gemini-2.5-flash-lite",
    name="safety_judge",
    instruction=SAFETY_JUDGE_INSTRUCTION,
)
judge_runner = None


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use LLM judge to evaluate response on multi-criteria.

    Scores response on SAFETY, RELEVANCE, ACCURACY, TONE (1-5 each).

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool), 'verdict' (str), 'scores' (dict),
        and 'reason' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": True, "verdict": "Judge not initialized — skipping",
                "scores": {}, "reason": ""}

    prompt = f"Evaluate this AI response for quality and safety:\n\n{response_text}"
    verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)

    # Parse scores from the multi-criteria format
    lines = verdict.strip().split("\n")
    scores = {}
    for line in lines:
        line = line.strip()
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            if key in ("SAFETY", "RELEVANCE", "ACCURACY", "TONE"):
                try:
                    scores[key] = int(val)
                except ValueError:
                    scores[key] = val

    # Extract verdict and reason
    is_pass = "PASS" in verdict.upper() and "FAIL" not in verdict.upper()
    reason = ""
    for line in lines:
        if line.strip().startswith("REASON:"):
            reason = line.strip().replace("REASON:", "").strip()

    return {
        "safe": is_pass,
        "verdict": "PASS" if is_pass else "FAIL",
        "scores": scores,
        "reason": reason,
    }


# ============================================================
# TODO 8: Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user."""

    def __init__(self, use_llm_judge=True):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = use_llm_judge and (safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user.

        Uses content_filter (regex PII) + llm_safety_check (multi-criteria LLM judge).
        PII redaction happens first, then judge evaluates the redacted version.
        """
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        # 1. Run content_filter — redact PII/secrets if found
        filter_result = content_filter(response_text)
        if filter_result["issues"]:
            self.redacted_count += 1
            print(f"  [OutputGuardrail] PII redacted: {filter_result['issues']}")
            # Replace content with redacted version
            if hasattr(llm_response, "content") and llm_response.content:
                llm_response.content.parts = [
                    types.Part.from_text(text=filter_result["redacted"])
                ]

        # 2. Run LLM-as-Judge (multi-criteria) if enabled
        if self.use_llm_judge:
            judge_result = await llm_safety_check(filter_result["redacted"])
            scores = judge_result.get("scores", {})
            if scores:
                print(f"  [LLM-Judge] SAFETY={scores.get('SAFETY','?')} "
                      f"RELEVANCE={scores.get('RELEVANCE','?')} "
                      f"ACCURACY={scores.get('ACCURACY','?')} "
                      f"TONE={scores.get('TONE','?')} "
                      f"→ {judge_result['verdict']}")
            if not judge_result["safe"]:
                self.blocked_count += 1
                print(f"  [LLM-Judge] BLOCKED: {judge_result.get('reason', '')}")
                if hasattr(llm_response, "content") and llm_response.content:
                    llm_response.content.parts = [
                        types.Part.from_text(
                            text="I cannot provide that information. "
                            "The response was flagged by our safety system."
                        )
                    ]
                return llm_response

        return llm_response


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses.

    Shows BEFORE vs AFTER for each test case so you can see
    what PII/secrets were detected and redacted.
    """
    test_responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    print("-" * 80)
    for resp in test_responses:
        result = content_filter(resp)
        if result["safe"]:
            print(f"  [SAFE] '{resp[:70]}'")
        else:
            print(f"  [ISSUES FOUND] BEFORE: '{resp[:70]}'")
            print(f"    Issues: {result['issues']}")
            print(f"    AFTER:  '{result['redacted'][:70]}'")
        print("-" * 80)


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
