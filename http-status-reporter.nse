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
  
  if not response then 
    return "No response received from the server." 
  end
  
  -- Safely extract status
  local status = response.status or "Unknown"
  if type(status) == "table" then
    status = table.concat(status, ", ")
  end
  
  -- Safely extract server header
  local server = "Unknown"
  if response.headers and response.headers["server"] then
    server = response.headers["server"]
    if type(server) == "table" then
      server = table.concat(server, ", ")
    end
  end
  
  local output = {}
  table.insert(output, "HTTP Status  : " .. tostring(status))
  table.insert(output, "Server Banner: " .. tostring(server))
  return stdnse.format_output(true, output)
end
