-- Verifiable task: is USDC holding its $1 peg?
-- Fetch USDC/USD from one venue and return the price in cents.
-- A healthy peg returns ~100; a result below 95 means depegged.

local r = tool.call("http_get", {
    url = "https://api.coingecko.com/api/v3/simple/price?ids=usd-coin&vs_currencies=usd&precision=4"
})

local data = json.decode_strings(r.body)
local price = data["usd-coin"].usd            -- e.g. "0.9997"

local dot = string.find_literal(price, ".")
local dollars = tonumber(string.sub(price, 1, dot - 1))
local cents = dollars * 100 + tonumber(string.sub(price, dot + 1, dot + 2))

return cents
