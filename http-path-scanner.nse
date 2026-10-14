description = [[
HTTP Target Path Scanner
Scans a specific URL path instead of the root directory.
]]
author = "Riya Aggarwal"
license = "Same as Nmap"
categories = {"safe", "discovery"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.http

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local response = http.get(host, port, path)
  if not response then return "No response received from path: " .. path end
  
  local output = {}
  table.insert(output, "HTTP Path Scan Report")
  table.insert(output, "Target IP   : " .. host.ip)
  table.insert(output, "Scanned Path: " .. path)
  table.insert(output, "HTTP Status : " .. (response.status or "Unknown"))
  table.insert(output, "Response Headers:")
  
  if response.headers then
    for key, value in pairs(response.headers) do
      table.insert(output, "  " .. key .. ": " .. value)
    end
  end
  return stdnse.format_output(true, output)
end
