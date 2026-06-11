cargo run -p proveno-orchestrator -- --prove --verbose \
  "Score wallet 0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa for onchain reputation.
   Check transaction count, token transfer activity, whether it has been flagged as scam, and ENS ownership.

   Use these free APIs (no API key needed, responses are small JSON):
   - Blockscout summary: https://eth.blockscout.com/api/v2/addresses/{address}
     Returns: coin_balance (string, wei), is_scam (bool), is_verified (bool), ens_domain_name (string or null), has_tokens (bool), reputation (string)
   - Blockscout counters: https://eth.blockscout.com/api/v2/addresses/{address}/counters
     Returns: transactions_count (string), token_transfers_count (string), gas_usage_count (string)

   IMPORTANT: Do NOT use the /token-balances endpoint (response too large). Use token_transfers_count from counters as a proxy for token diversity.
   IMPORTANT: All numeric values from these APIs are returned as STRINGS. Always use tonumber() before comparing.

   Return a score from 0-100 with breakdown."
