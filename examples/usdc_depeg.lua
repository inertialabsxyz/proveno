-- usdc_depeg.lua: prove USDC's price in cents from a single venue.
--
-- Straight-line over one small response, so it stays inside the proving
-- envelope (no if/and: see GH #64; small body: see GH #65). `precision=4`
-- forces a "D.FFFF" string, so the cents parse needs no branching.
--
-- Peg floor is 95 cents; a healthy USDC returns ~100. A result below 95
-- means depegged. (The full multi-venue >=2-of-3 resolution is the #57
-- flagship and is grant scope, not this demo task.)

local r = tool.call("http_get", {
    url = "https://api.coingecko.com/api/v3/simple/price?ids=usd-coin&vs_currencies=usd&precision=4"
})

local data = json.decode_strings(r.body)
local price = data["usd-coin"].usd            -- e.g. "0.9997"

local dot = string.find_literal(price, ".")
local dollars = tonumber(string.sub(price, 1, dot - 1))
local cents = dollars * 100 + tonumber(string.sub(price, dot + 1, dot + 2))

return cents
