-- eth_price.lua — fetch ETH/USD and prove whether it cleared $3,000.
--
-- A deliberately straight-line task that proves cleanly end-to-end:
--   * uses CoinGecko's `simple/price` endpoint (tiny response body), and
--   * avoids `if`/`and`/`or` control flow.
-- Both constraints are load-bearing today — see GH issues for the circuit
-- completeness bugs around conditional jumps (next_pc @139) and large
-- tool-response hashing (tool_responses_hash @186). Keep this example
-- straight-line + small-response until those land.

local r = tool.call("http_get", {
    url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
})

local data = json.decode_strings(r.body)

-- `decode_strings` keeps numbers as strings (the VM is integer-only). Append
-- a fractional part so there is always a "." to split on, then take the
-- integer dollars before it.
local price = data.ethereum.usd .. ".00"
local dot = string.find_literal(price, ".")
local dollars = tonumber(string.sub(price, 1, dot - 1))

return dollars
