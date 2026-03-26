-- tls_test.lua: test TLS attestation capture with a real HTTPS request.
--
-- Uses a P-256 ECDSA server (Cloudflare) so TLS attestation is captured.
-- Servers using RSA certs (e.g. httpbin.org) won't produce attestation data.

local resp = tool.call("http_get", {url = "https://one.one.one.one/"})
log("status: " .. tostring(resp.status))

if resp.status ~= 200 then
    error("HTTP request failed with status " .. tostring(resp.status))
end

return {status = resp.status}
