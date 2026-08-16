#!/usr/bin/env python3
"""Generate window-max-breach Lua programs for benchmarking the Proveno
proving pipeline.

Two modes, to probe where the proven boundary actually sits:

  harness : observations are decoded with the builtin `json.decode` (one opaque
            VM step), then a Lua loop finds the windowed max. The parsing work
            happens in host Rust, OUTSIDE the trace.

  inlua   : observations arrive as a raw string, and the Lua program parses the
            bytes itself with `string.byte` in a scan loop. The parsing work now
            happens as VM steps, INSIDE the trace.

Deterministic: prices are a fixed integer sequence (no RNG), so the same args
always produce the same program and the same trace length.

Usage:
  gen.py --mode harness --n 6    --window 4    --threshold 10200 -o out.lua
  gen.py --mode inlua   --n 5000 --window 5000 --threshold 10200 -o out.lua
"""
import argparse


def prices(n: int) -> list[int]:
    # Deterministic pseudo-wave around 10000 in integer minor units (cents).
    # No floats, no RNG: value depends only on the index.
    out = []
    for i in range(n):
        # a bounded, non-monotonic sequence so the windowed max is non-trivial
        v = 10000 + ((i * 37) % 500) - 250 + ((i * i) % 91)
        out.append(v)
    return out


def observations_json(n: int) -> str:
    ps = prices(n)
    parts = []
    base_t = 1718750000
    for i, p in enumerate(ps):
        parts.append('{"t":%d,"p":%d}' % (base_t + i * 60, p))
    return "[" + ",".join(parts) + "]"


def gen_harness(n: int, window: int, threshold: int) -> str:
    obs = observations_json(n)
    return f"""-- BENCH (harness-decode): {n} observations, WINDOW {window}.
-- json.decode runs in the host (one opaque VM step); only the windowing loop
-- is in the trace.
local OBSERVATIONS = json.decode([[
{obs}
]])

local THRESHOLD = {threshold}
local WINDOW = {window}

local n = #OBSERVATIONS
local start = n - WINDOW + 1
if start < 1 then start = 1 end

local window_max = nil
local window_max_t = nil
for i = start, n do
    local obs = OBSERVATIONS[i]
    local price = obs.p
    if window_max == nil or price > window_max then
        window_max = price
        window_max_t = obs.t
    end
end

local breached = window_max >= THRESHOLD
if breached then return window_max end
return 0
"""


def gen_inlua(n: int, window: int, threshold: int) -> str:
    obs = observations_json(n)
    # The raw observations live as a Lua long-bracket string literal. The program
    # parses it byte-by-byte with string.byte: every byte scanned is a builtin
    # call = a VM step, so the parse cost lands INSIDE the trace.
    #
    # Format is [{"t":<int>,"p":<int>},...]. We scan integers in order; they
    # alternate t, p, t, p, ... so every 2nd integer is a price. We keep a
    # rolling record of the last WINDOW prices and take their max.
    return f"""-- BENCH (in-Lua parse): {n} observations, WINDOW {window}.
-- The observations arrive as a raw string; the program parses the bytes itself
-- with string.byte, so the parsing work is IN the trace (one step per byte).
local RAW = [[
{obs}
]]

local THRESHOLD = {threshold}
local WINDOW = {window}

local len = string.len(RAW)

-- Rolling buffer of the last WINDOW prices (1-indexed ring).
local buf = {{}}
local count = 0          -- total prices parsed
local idx = 0            -- 0-based index of the current integer (t=even, p=odd)

-- Byte scanner: accumulate digit runs into integers.
local i = 1
local in_num = false
local cur = 0
while i <= len do
    local b = string.byte(RAW, i)
    if b >= 48 and b <= 57 then          -- '0'..'9'
        cur = cur * 10 + (b - 48)
        in_num = true
    else
        if in_num then
            -- finished an integer; odd index => price
            if (idx % 2) == 1 then
                count = count + 1
                local slot = (count - 1) % WINDOW + 1
                buf[slot] = cur
            end
            idx = idx + 1
            cur = 0
            in_num = false
        end
    end
    i = i + 1
end
if in_num then
    if (idx % 2) == 1 then
        count = count + 1
        local slot = (count - 1) % WINDOW + 1
        buf[slot] = cur
    end
end

-- Max over the retained window (last min(count,WINDOW) prices).
local kept = count
if kept > WINDOW then kept = WINDOW end
local window_max = nil
local k = 1
while k <= kept do
    local v = buf[k]
    if window_max == nil or v > window_max then
        window_max = v
    end
    k = k + 1
end
if window_max == nil then window_max = 0 end

local breached = window_max >= THRESHOLD
if breached then return window_max end
return 0
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["harness", "inlua"], required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--window", type=int, required=True)
    ap.add_argument("--threshold", type=int, default=10200)
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    src = (gen_harness if a.mode == "harness" else gen_inlua)(a.n, a.window, a.threshold)
    with open(a.out, "w") as f:
        f.write(src)
    print(f"wrote {a.out} ({a.mode}, n={a.n}, window={a.window}, {len(src)} bytes)")


if __name__ == "__main__":
    main()
