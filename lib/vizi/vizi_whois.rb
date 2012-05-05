# This gem module provides a classes to find the right Regional Internet Registry
# for a given IP Address. The query method will navigate each major RIR until a 
# response is found.
#
# Author::    Al Kivi <al.kivi@vizitrax.com>
# License::   MIT

module Vizi
# This class includes a set of methods to navigate and query the regional whois servers
  class Gowhois
 
# This method will navigate each whois server until a response is found  
    def query (ipaddr)
      s = "arin"
      response = ruby_whois(ipaddr, s)
      if response.index("(NET")        # look for dual NET blocks in ARIN responses
        t1 = response
        netaddrs = response.scan(/\(NET-\w+\-\w+\-\w+\-\w+\-\w+\)/)
        netaddr = netaddrs[netaddrs.length-1].scan(/NET-\w+\-\w+\-\w+\-\w+\-\w+/)
        response = ruby_whois(netaddr[0], s)
      end
      if response.index("whois.ripe.net")
        s = "ripe"
        response = ruby_whois(ipaddr, s)
      elsif response.index("whois.apnic.net")
        s = "apnic"
        response = ruby_whois(ipaddr, s)
      elsif response.index("whois.lacnic.net")
        s = "lacnic"
        response = ruby_whois(ipaddr, s)
        if response.length > 4000     # parse very long responses
          lines = response.split(/\r\n/)
          lines.delete_if { |e| e =~ /nserver:/ }
          lines.delete_if { |e| e =~ /nsstat:/ }
          lines.delete_if { |e| e =~ /nslastaa:/ }
          lines.delete_if { |e| e =~ /inetrev:/ }
          response=""
          i=0
          while i<lines.length
            response = response+lines[i]+"\r\n"
            i = i+1
          end
        end
      elsif response.index("afrinic.net")
        s = "afrinic"
        response = ruby_whois(ipaddr, s)
      elsif response.length >250 and response.length < 500
        str = response[100..250]
        x = str.index("(")
        y = str.index(")")
        if x != nil and y != nil
          net = str[x+1..y-1]
          response = ruby_whois(net, s)
        end
      end
      ccode = get_country(response)
      return response, ccode, s
    end

# This method will parse the response to find the two character country code
    def get_country (response)
      temp = response.upcase
      temp.delete!("\t")
      temp.delete!(" ")
      x = temp.index("COUNTRY:")
      ccode = nil
      if x != nil
        ccode = temp[x+8..x+9]
      elsif temp.index(".BR")
        ccode = "BR"
      else
        ccode ="?"
      end
      return ccode
    end

# This method the ruby version of the whois command function
    def ruby_whois (send_string, host)
#    p send_string + " .. " + host
      if host.index(".") == nil
        host = "whois."+host+".net"
      end
      add_string = ""
      add_string = "n " if host == "whois.arin.net"
      add_string = "n ! " if send_string.index("NET") == 0
      s = TCPSocket.open(host,43) 
      s.write(add_string+send_string+"\n")
      ret = ""
      while s.gets do
        ret += $_
      end
      s.close
      return ret
    rescue # rescue logic if not found
      ret="Not found"
      return ret
    end

  end
  
# This class will parse the response string from a Whois server
  class Formatter
  
		def initialize
  		@cities = YAML.load_file("config/cities.yml")
  	end	
 
# This method will parse response string 
#    def parse (contents, country, server)
    def parse (contents, country)
      name_list = ["COUNTRY","NETNAME","ORGNAME","ORG-NAME","CUSTNAME","OWNER","ADDRESS","DESCR","CITY","STATEPROV","POSTALCODE"]
      country_list = ["GERMANY","UNITED KINGDOM","UK","ENGLAND","INDIA","NETHERLANDS","SPAIN","BELGIUM","PR CHINA","NORWAY"]
      odd_words = ["ABUSE", "PHISH", "SPAM", "ACTIVITY","PROVINCE NETWORK","COMMUNICATION DIVISION","IMPROPER","SERVICE PROVIDER","IP POOL","-----","*****","#####","IP ASSIGNMENT","FOR CUSTOMER","THIS SPACE"]
			trim_orgname = ["LIMITED", "LTD", "INC", "CORPORATION", "LLC", "HOLDINGS", "UNICATIONS", "INFORMATION CENTER"]
#      formatted_file = File.open('./log/formatted.log', 'a')
      a = contents.upcase.split(/\n/) 
      i = -1
      line = [nil,nil]
      lastname = nil
      orgname = nil
      cityflag = false
      addressflag = false
      country_count = 0
      da_count = 0
      netname_count = 0
      darray = []
      outstring = ""         
      while i < a.length-1
        i = i + 1
        line = [nil, nil]
        goodline = true
        current = a[i].chomp
        if current.length < 2
          goodline = false        
        else
					goodline = false if current[0] == "%" or current[0] == "#"
        end
        if goodline
          line = current.split(":")    
          line_name = line[0]
          line_value = line[1]
          line_value = line_value.strip if not line_value.nil?
          if line_value.nil?
            line_value = "" 
            if lastname == "ADDRESS" and line_name != line_name.lstrip
              line_name = lastname
            end         
          else
						addressflag = true if line_name == "ADDRESS"
          end
          odd_words.each {|w|
						goodline = false if line_value.index(w)			
					}	          
            		             
          if line_name == "COUNTRY"
						country_count = country_count + 1
						line_value = line_value[0..1] if not line_value.nil?          
          end
          if line_name == "NETNAME"
						netname_count = netname_count + 1 
						netname = line_value if netname_count == 1
          end

					if not ["NETNAME","POSTALCODE"].index(line_name)
						line_value = line_value.lstrip.gsub(",",";")
						line_value = line_value.lstrip.gsub(".","")
						line_value = line_value.lstrip.gsub("; ",";")			
						line_value = line_value.lstrip.gsub(" ;",";")
						line_value = line_value.lstrip.gsub("/",";")
#						line_value = line_value.lstrip.gsub("-",";")																		
						line_value = line_value.chomp(";")
					end
          if ["ORGNAME","CUSTNAME","OWNER","ORG-NAME"].index(line_name)
						orgname = (line_value + ";").split(";")[0]
					end					
          if line_name == "DESCR" or line_name == "ADDRESS"
						goodline = false if line_value.length == 0
						goodline = false if da_count > 6          
            goodline = false if darray.index(line_value)         
						if goodline
							darray << line_value
							da_count = da_count + 1
						end
					end
						          
          goodline = false if country_count > 1 and line_name == "COUNTRY"
          goodline = false if netname_count > 1 and line_name == "NETNAME"                          
          goodline = false if line_value[0] == "-"
          goodline = false if country_list.index(line_value)
          goodline = false if line_name == "ADDRESS" and line_value == country
          goodline = false if addressflag and line_name == "DESCR"
          goodline = false if line_value.length < 2 

          cityflag = true if line_name == "CITY" and line_value.length > 0
        else
          line_name = current
          line_value = ""
        end         
        lastname = line_name  
        if goodline
          if name_list.index(line_name)
            newline = line_name + ': ' + line_value + '\n'
            outstring = outstring + newline       
          end
        end      
      end 
      
#     At the end of regular parse, find organization NAME if needed    
			if orgname.nil?
				if darray[0].nil?
					orgname = 'NOT FOUND'
				else
					orgname = (darray[0] + ";").split(";")[0]				
				end
			end     
       
			if country != "CA" and country != "US" and not orgname[/[0123456789]/].nil? 
				orgname = netname if not netname.nil?
			end 
      
			trim_orgname.each {|p|
				orgname = orgname.sub(p, "")
			}
			orgname = orgname.sub(".","")
			orgname = orgname[0..29]
			orgname = orgname[0..28-orgname.reverse.index(" ")] if not orgname.reverse.index(" ").nil?    
      
			newline = 'NAME: ' + orgname + '\n'
			outstring = outstring + newline

# 		Search for city name, if not identified  		
      if country != "CA" and country != "US"
				if not cityflag             
					candidates = @cities["."+country]
					city = "UNKNOWN"
					if not darray[0].nil? and not candidates.nil?
						darray.each {|line|
							candidates.each {|c|
								city = c.delete("!") if c.class != Hash and line.index(c.delete("!"))
								break if city != 'UNKNOWN'
							}
						}
					end
					if city == "UNKNOWN" and not candidates.nil?
						candidates.each {|c|
							if c.class == String
								city = c.delete("!") if c.index("!")
								break if city != 'UNKNOWN'
							end
						}
					end
					newline = 'CITY: ' + city + '\n'
					outstring = outstring + newline       
				end
      end
      
      return outstring         
    end
    
    def createhash(formatted)
			farray = formatted.split('\n')
			hashout = Hash.new
			farray.each {|x|
	      line = x.split(': ')		
			  hashout[line[0]] = line[1]
			}
			hashout['NAME'] = '??' if hashout['NAME'].nil?	
			hashout['CITY'] = '??' if hashout['CITY'].nil?				
			hashout['COUNTRY'] = '??' if hashout['COUNTRY'].nil?						
			hashout
    end
  end
      
end

