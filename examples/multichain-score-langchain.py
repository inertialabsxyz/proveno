"""
LangChain multi-chain wallet scoring — 8 API calls.
Compare token usage against proveno's single-shot approach.

Usage:
    pip install -r requirements.txt
    python examples/multichain-score-langchain.py
"""

from pathlib import Path

from dotenv import load_dotenv

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

task = f"""Score wallet {WALLET} for multi-chain onchain reputation.

For EACH of the following chains, fetch BOTH the address summary and the counters:

- Ethereum summary: https://eth.blockscout.com/api/v2/addresses/{WALLET}
- Ethereum counters: https://eth.blockscout.com/api/v2/addresses/{WALLET}/counters
- Optimism summary: https://optimism.blockscout.com/api/v2/addresses/{WALLET}
- Optimism counters: https://optimism.blockscout.com/api/v2/addresses/{WALLET}/counters
- Base summary: https://base.blockscout.com/api/v2/addresses/{WALLET}
- Base counters: https://base.blockscout.com/api/v2/addresses/{WALLET}/counters
- Arbitrum summary: https://arbitrum.blockscout.com/api/v2/addresses/{WALLET}
- Arbitrum counters: https://arbitrum.blockscout.com/api/v2/addresses/{WALLET}/counters

That is 8 API calls total. You MUST make all 8.

From each chain's summary use: coin_balance, is_scam, ens_domain_name, has_tokens
From each chain's counters use: transactions_count, token_transfers_count

IMPORTANT: All numeric values from these APIs are returned as STRINGS.
IMPORTANT: Do NOT use the /token-balances endpoint.

Return a JSON object with:
- per_chain: object with a key per chain, each containing tx_count, token_transfers, has_balance (bool), score (0-100)
- overall_score: 0-100 weighted average
- summary: one sentence explanation"""

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
