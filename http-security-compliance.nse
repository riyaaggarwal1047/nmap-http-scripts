kdescription = [[
HTTP Information Scanner

Performs a basic scan of an HTTP service. Retrieves the HTTP status code,
server banner, and all response headers. This script only gathers and 
displays information without performing any security auditing or compliance checks.
]]

author = "Riya Aggarwal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

-- Run this script on any HTTP or HTTPS port
portrule = shortport.http

action = function(host, port)
  local output = {}
  
  -- Make an HTTP GET request to the root directory
  local response = http.get(host, port, "/")
  
  if not response then
    return "No response received from the server."
  end
  
  table.insert(output, "=========================================================")
  table.insert(output, "HTTP Scan Report")
  table.insert(output, "=========================================================")
  table.insert(output, "Target IP   : " .. host.ip)
  table.insert(output, "Port        : " .. port.number)
  table.insert(output, "Protocol    : " .. port.protocol)
  table.insert(output, "State       : " .. port.state)
  table.insert(output, "HTTP Status : " .. (response.status or "Unknown"))
  table.insert(output, "=========================================================")
  table.insert(output, "Response Headers:")
  
  -- Iterate through all returned headers and print them
  if response.headers then
    for key, value in pairs(response.headers) do
      table.insert(output, "  " .. key .. ": " .. value)
    end
  else
    table.insert(output, "  No headers returned.")
  end
  
  table.insert(output, "=========================================================")
  
  return stdnse.format_output(true, output)
end
