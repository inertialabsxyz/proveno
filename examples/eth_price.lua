-- Verifiable task: what is ETH worth in whole dollars?
-- Fetch ETH/USD from one venue and return the integer dollar price.

local r = tool.call("http_get", {
    url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
})

local data = json.decode_strings(r.body)

-- Numbers decode as strings (the VM is integer-only); take the whole-dollar
-- part before the decimal point.
local price = data.ethereum.usd .. ".00"
local dot = string.find_literal(price, ".")
local dollars = tonumber(string.sub(price, 1, dot - 1))

return dollars
