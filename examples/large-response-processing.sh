cargo run -p proveno-orchestrator -- --prove --verbose --gas-limit 10000000 --max-tool-calls 16 \
  "Analyze wallet 0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa across 4 chains.

   For each chain, fetch 3 endpoints (12 calls total):
   1. Summary: https://{chain}.blockscout.com/api/v2/addresses/{WALLET}
   2. Counters: https://{chain}.blockscout.com/api/v2/addresses/{WALLET}/counters
   3. Tokens: https://{chain}.blockscout.com/api/v2/addresses/{WALLET}/tokens?type=ERC-20

   Chains: eth, base, arbitrum, optimism
   WALLET = 0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa

   From summary: coin_balance, is_scam, ens_domain_name, has_tokens
   From counters: transactions_count, token_transfers_count
   From tokens: items array — count items, count those with non-nil token.exchange_rate

   IMPORTANT: All API values are STRINGS. Use tonumber() before math.

   Per chain compute: tx_count, token_transfers, has_balance, num_tokens, priced_tokens, chain_score (0-100)

   Return: per_chain (table), total_tokens, total_tx_count, overall_score (0-100), summary (one sentence)"
