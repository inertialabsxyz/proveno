"""
LangChain large-response processing benchmark — 12 API calls with substantial payloads.

Fetches token portfolio data (summary + counters + ERC-20 token list) from 4 chains.
Token list responses are ~5-25KB each of JSON with 50+ token entries.
In LangChain's ReAct loop, every API response is appended to the conversation
context and sent back to the LLM, accumulating ~50-70KB of data across iterations.

Compare against: examples/large-response-processing.sh (proveno)

Usage:
    pip install -r requirements.txt
    python examples/large-response-langchain.py
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

task = f"""Analyze the full token portfolio and activity for wallet {WALLET} across multiple chains.

For EACH of the following chains, fetch THREE endpoints:

Ethereum:
- Summary: https://eth.blockscout.com/api/v2/addresses/{WALLET}
- Counters: https://eth.blockscout.com/api/v2/addresses/{WALLET}/counters
- Tokens: https://eth.blockscout.com/api/v2/addresses/{WALLET}/tokens?type=ERC-20

Base:
- Summary: https://base.blockscout.com/api/v2/addresses/{WALLET}
- Counters: https://base.blockscout.com/api/v2/addresses/{WALLET}/counters
- Tokens: https://base.blockscout.com/api/v2/addresses/{WALLET}/tokens?type=ERC-20

Arbitrum:
- Summary: https://arbitrum.blockscout.com/api/v2/addresses/{WALLET}
- Counters: https://arbitrum.blockscout.com/api/v2/addresses/{WALLET}/counters
- Tokens: https://arbitrum.blockscout.com/api/v2/addresses/{WALLET}/tokens?type=ERC-20

Optimism:
- Summary: https://optimism.blockscout.com/api/v2/addresses/{WALLET}
- Counters: https://optimism.blockscout.com/api/v2/addresses/{WALLET}/counters
- Tokens: https://optimism.blockscout.com/api/v2/addresses/{WALLET}/tokens?type=ERC-20

That is 12 API calls total. You MUST make all 12.

From each summary, extract: coin_balance (string), is_scam (bool), ens_domain_name, has_tokens (bool)
From each counters, extract: transactions_count (string), token_transfers_count (string)
From each tokens response, extract the 'items' array. Each item has:
- token.name, token.symbol, token.exchange_rate (string or null), token.decimals, value (raw balance)

For each chain, compute:
- tx_count: from counters
- token_transfers: from counters
- has_balance: coin_balance > 0
- num_tokens: count of items in token list
- priced_tokens: count of tokens with non-null exchange_rate
- is_scam: from summary
- chain_score: 0-100 based on tx_count, token diversity, and balance

Return a JSON object with:
- per_chain: object keyed by chain name with the stats above
- total_tokens: sum of num_tokens across all chains
- total_priced_tokens: sum of priced_tokens across all chains
- total_tx_count: sum of tx_count across all chains
- overall_score: 0-100 weighted average
- summary: two sentence explanation of the wallet's cross-chain portfolio"""

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
