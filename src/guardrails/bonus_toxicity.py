"""
Bonus Layer: Toxicity Classifier (6th safety layer)

Detects toxic, hateful, harassing, or otherwise harmful language
in both user input and agent output using LLM-as-Judge.

Why this is needed:
- Input guardrails catch prompt injection, but NOT toxic language.
- Output guardrails catch PII, but NOT subtle toxicity (microaggressions,
  passive-aggressive language, gaslighting).
- A banking AI that responds to toxic users or generates toxic output
  creates legal and reputational risk.
- Dedicated toxicity classifiers (Perspective API, detoxify) catch
  patterns that regex and general-purpose LLM judges miss.
"""
from google.adk.plugins import base_plugin
from google.adk.agents import llm_agent
from google.adk import runners
from google.genai import types
from google.adk.agents.invocation_context import InvocationContext

from core.utils import chat_with_agent


TOXICITY_JUDGE_INSTRUCTION = """You are a content moderation classifier for a banking AI assistant.
Your job is to detect toxic, harmful, or inappropriate content.

When you receive a message, classify it for these categories:
1. TOXICITY: Personal attacks, insults, harassment, hate speech
2. THREAT: Threats of violence, harm, or intimidation
3. PROFANITY: Excessive swearing or vulgar language
4. SEXUAL: Sexually explicit or inappropriate content
5. SPAM: Repetitive, meaningless, or advertising content

Respond in EXACTLY this format:
IS_TOXIC: YES or NO
CATEGORY: <category name or "none">
CONFIDENCE: <1-5>
REASON: <one sentence>
"""

# Lazy-init globals
_toxicity_judge_agent = None
_toxicity_judge_runner = None


def _ensure_toxicity_judge():
    """Initialize the toxicity judge agent on first use."""
    global _toxicity_judge_agent, _toxicity_judge_runner
    if _toxicity_judge_agent is None:
        _toxicity_judge_agent = llm_agent.LlmAgent(
            model="gemini-2.5-flash-lite",
            name="toxicity_judge",
            instruction=TOXICITY_JUDGE_INSTRUCTION,
        )
        _toxicity_judge_runner = runners.InMemoryRunner(
            agent=_toxicity_judge_agent,
            app_name="toxicity_judge",
        )


async def check_toxicity(text: str) -> dict:
    """Check if text contains toxic content using LLM judge.

    Args:
        text: The text to check (user input or agent output)

    Returns:
        dict with 'is_toxic' (bool), 'category' (str), 'confidence' (int),
        and 'reason' (str)
    """
    _ensure_toxicity_judge()

    verdict, _ = await chat_with_agent(
        _toxicity_judge_agent, _toxicity_judge_runner,
        f"Classify this content for toxicity:\n\n{text}",
    )

    # Parse the structured response
    lines = verdict.strip().split("\n")
    result = {
        "is_toxic": False,
        "category": "none",
        "confidence": 0,
        "reason": "",
    }

    for line in lines:
        line = line.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().upper()
        val = val.strip()

        if key == "IS_TOXIC":
            result["is_toxic"] = val.upper() == "YES"
        elif key == "CATEGORY":
            result["category"] = val.lower()
        elif key == "CONFIDENCE":
            try:
                result["confidence"] = int(val)
            except ValueError:
                result["confidence"] = 0
        elif key == "REASON":
            result["reason"] = val

    return result


class ToxicityGuardPlugin(base_plugin.BasePlugin):
    """Plugin that detects toxic content in user input and agent output.

    Catches: hate speech, harassment, threats, profanity, sexual content.
    Input filtering blocks toxic users before they reach the LLM.
    Output filtering ensures the agent doesn't generate toxic responses.
    """

    def __init__(self, block_input=True, block_output=True):
        super().__init__(name="toxicity_guard")
        self.block_input = block_input
        self.block_output = block_output
        self.blocked_count = 0
        self.total_input_count = 0
        self.total_output_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check user input for toxic content."""
        if not self.block_input:
            return None

        self.total_input_count += 1

        text = ""
        if user_message and user_message.parts:
            for part in user_message.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text

        if not text:
            return None

        result = await check_toxicity(text)
        if result["is_toxic"]:
            self.blocked_count += 1
            print(f"  [ToxicityGuard] BLOCKED input: {result['category']} "
                  f"(confidence: {result['confidence']}/5)")
            return self._block_response(
                "I cannot process this request. "
                "Please communicate respectfully and keep discussions "
                "related to banking services."
            )

        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        """Check agent output for toxic content."""
        if not self.block_output:
            return llm_response

        self.total_output_count += 1

        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text

        if not text:
            return llm_response

        result = await check_toxicity(text)
        if result["is_toxic"]:
            self.blocked_count += 1
            print(f"  [ToxicityGuard] BLOCKED output: {result['category']} "
                  f"(confidence: {result['confidence']}/5)")
            if hasattr(llm_response, "content") and llm_response.content:
                llm_response.content.parts = [
                    types.Part.from_text(
                        text="I apologize, but I am unable to provide that "
                        "response as it may contain inappropriate content. "
                        "How else can I help you with banking?"
                    )
                ]

        return llm_response

    @property
    def stats(self) -> dict:
        return {
            "blocked": self.blocked_count,
            "total_input": self.total_input_count,
            "total_output": self.total_output_count,
        }
