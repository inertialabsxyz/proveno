cargo run -p proveno-orchestrator -- --prove --verbose \
  "Score wallet 0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa for multi-chain onchain reputation.

   For EACH of the following chains, fetch BOTH the address summary and the counters:

   - Ethereum summary: https://eth.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa
   - Ethereum counters: https://eth.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa/counters
   - Optimism summary: https://optimism.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa
   - Optimism counters: https://optimism.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa/counters
   - Base summary: https://base.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa
   - Base counters: https://base.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa/counters
   - Arbitrum summary: https://arbitrum.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa
   - Arbitrum counters: https://arbitrum.blockscout.com/api/v2/addresses/0x11E4857Bb9993a50c685A79AFad4E6F65D518DDa/counters

   That is 8 API calls total. You MUST make all 8.

   From each chain's summary use: coin_balance, is_scam, ens_domain_name, has_tokens
   From each chain's counters use: transactions_count, token_transfers_count

   IMPORTANT: All numeric values from these APIs are returned as STRINGS. Always use tonumber() before comparing.
   IMPORTANT: Do NOT use the /token-balances endpoint (response too large).

   Return a table with:
   - per_chain: table with a key per chain, each containing tx_count, token_transfers, has_balance (bool), score (0-100)
   - overall_score: 0-100 weighted average
   - summary: one sentence explanation"
