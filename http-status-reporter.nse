description = [[
HTTP Status & Server Banner Reporter
Extracts only the HTTP status code and server banner.
]]
author = "Riya Aggarwal"
license = "Same as Nmap"
categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response then return "No response received." end
  
  local status = response.status or "Unknown"
  local server = response.headers["server"] or "Unknown"
  
  local output = {}
  table.insert(output, "HTTP Status  : " .. status)
  table.insert(output, "Server Banner: " .. server)
  return stdnse.format_output(true, output)
end
