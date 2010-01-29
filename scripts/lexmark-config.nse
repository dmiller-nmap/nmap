description = [[ Retrieve Lexmark S300-S400 Configuration ]]

-- The Lexmark S302 was found to respond with it's configuration to the NTPRequest probe
-- As the response decodes as MDNS the request was modified to resemble a MDNS request as close as possible
-- However, the port (9100/udp) is listed as something completely different (HBN3) in documentation from Lexmark
-- http://www.lexmark.com/vgn/images/portal/Security%20Features%20of%20Lexmark%20MFPs%20v1_1.pdf

---
--@output
-- Interesting ports on 192.168.1.111:
-- PORT     STATE   SERVICE REASON
-- 9100/udp unknown unknown unknown-response
-- | lexmark-config:  
-- |   IPADDRESS: 10.46.200.170
-- |   IPNETMASK: 255.255.255.0
-- |   IPGATEWAY: 10.46.200.2
-- |   IPNAME: "ET0020006E4A37"
-- |   MACLAA: "000000000000"
-- |   MACUAA: "0004007652EC"
-- |   MDNSNAME: "S300-S400 Series (32)"
-- |   ADAPTERTYPE: 2
-- |   IPADDRSOURCE: 1
-- |   ADAPTERCAP: "148FC000"
-- |   OEMBYTE: 1 0
-- |   PASSWORDSET: FALSE
-- |   NEWPASSWORDTYPE: TRUE
-- |   1284STRID: 1 "S300-S400 Series"
-- |   CPDATTACHED: 1 1
-- |   SECUREMODE: FALSE
-- |   PRINTERVIDPID: 1 "043d0180"
-- |_  product=(S300-S400: Series)

-- Version 0.3
-- Created 01/03/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/13/2010 - v0.2 - revised script to use dns library
-- Revised 01/23/2010 - v0.3 - revised script to use the proper ports

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'dns'

portrule = shortport.portnumber({5353,9100}, "udp")

action = function( host, port )
			
	
	local catch = function()
		stdnse.print_debug("lexmark-config failed to retrieve configuration")
	end

	local try = nmap.new_try(catch)

	local result = {}	
	local response = try( dns.query( "", { port = port.number, host = host.ip, dtype="PTR", retPkt=true} ) )
	local txtrecords = try( dns.findNiceAnswer( dns.types.TXT, response, true ) )
	
	for _, v in ipairs( txtrecords ) do
		if ( v:len() > 0 ) then
			if v:find("PRINTERVIDPID") then
				port.version.name="hbn3"
			end
			if not v:find("product=") then					
				v = v:gsub(" ", ": ", 1)
			end	
			table.insert( result, v )
		end
	end
	
	-- set port to open
    nmap.set_port_state(host, port, "open")
	nmap.set_port_version(host, port, "hardmatched")
	
	return stdnse.format_output(true, result)
end

