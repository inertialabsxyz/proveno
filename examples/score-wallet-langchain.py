"""
LangChain equivalent of the proveno wallet scoring demo.

Compares token usage between a traditional ReAct agent loop
and proveno's single-shot program generation approach.

Usage:
    pip install langchain langchain-anthropic langgraph requests python-dotenv
    python examples/score-wallet-langchain.py
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import requests
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

WALLET = "0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa"


@tool
def http_get(url: str) -> str:
    """Fetch a URL and return the response body as a string."""
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


llm = ChatAnthropic(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
)

agent = create_react_agent(llm, [http_get])

task = f"""Score wallet {WALLET} for onchain reputation.
Check transaction count, token transfer activity, whether it has been flagged as scam, and ENS ownership.

Use these free APIs (no API key needed, responses are small JSON):
- Blockscout summary: https://eth.blockscout.com/api/v2/addresses/{WALLET}
  Returns: coin_balance (string, wei), is_scam (bool), is_verified (bool), ens_domain_name (string or null), has_tokens (bool), reputation (string)
- Blockscout counters: https://eth.blockscout.com/api/v2/addresses/{WALLET}/counters
  Returns: transactions_count (string), token_transfers_count (string), gas_usage_count (string)

IMPORTANT: Do NOT use the /token-balances endpoint (response too large). Use token_transfers_count from counters as a proxy for token diversity.

Return a score from 0-100 with breakdown."""

result = agent.invoke({"messages": [("user", task)]})

# Print the final response
for msg in result["messages"]:
    if hasattr(msg, "content") and isinstance(msg.content, str) and msg.content:
        last_text = msg.content
print("\n── Result ─────────────────────────────────────")
print(last_text)

# Collect token usage from all LLM calls
total_in = 0
total_out = 0
llm_calls = 0
for msg in result["messages"]:
    if hasattr(msg, "usage_metadata") and msg.usage_metadata:
        u = msg.usage_metadata
        total_in += u.get("input_tokens", 0)
        total_out += u.get("output_tokens", 0)
        llm_calls += 1

print("\n── Token Usage ────────────────────────────────")
print(f"  LLM calls:     {llm_calls}")
print(f"  Input tokens:  {total_in:,}")
print(f"  Output tokens: {total_out:,}")
print(f"  Total tokens:  {total_in + total_out:,}")
