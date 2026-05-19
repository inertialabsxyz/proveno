local r = tool.call("http_get", {url = "https://httpbin.org/json"})
return r.status
