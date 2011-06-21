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
      elsif response.index("whois.afrinic.net")
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
 
# This method will parse response string 
    def parse (contents, country, server)
      name_list = ["COUNTRY","NETNAME","ORGNAME","ORG-NAME","CUSTNAME","OWNER","ADDRESS","DESCR","CITY","STATEPROV","POSTALCODE"]
      country_list = ["GERMANY","UNITED KINGDOM","UK","ENGLAND","INDIA","NETHERLANDS","SPAIN","BELGIUM","PR CHINA","NORWAY"]
      odd_list = ["EMAIL","CONTA","PHONE","ABUSE ","SENT ","SEND ","DATE ","ATTN ","INFRA","THIS ","ANTIA","*****","-----"]

      formatted_file = File.open('./log/formatted.log', 'a')

      a = contents.upcase.split(/\n/) 
      i = -1
      line = [nil,nil]
      lastname = nil
      addressflag = false
      country_count = 0
      da_count = 0
      netname_count = 0
      darray = []
      outstring = "" 
      formatted_file.puts '+ ------------------------------------------------------'
      formatted_file.puts '+ '+ country + ' - ' + server.upcase
      formatted_file.puts '+ ------------------------------------------------------'         
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
          if line[1].nil?
            line[1] = "" 
            if lastname == "ADDRESS" and line[0] != line[0].lstrip
              line[0] = lastname
            end         
          else
			addressflag = true if line[0] == "ADDRESS"
          end 
		  line[1] = line[1].lstrip.gsub(".","")
		  line[1] = line[1].lstrip.gsub(", ",",")
		  line[1] = line[1].lstrip.gsub(" ,",",")
		  line[1] = line[1].chomp(",")	  		            
          country_count = country_count + 1 if line[0] == "COUNTRY"
          da_count = da_count + 1 if line[0] == "DESCR" or line[0] == "ADDRESS"
          netname_count = netname_count + 1 if line[0] == "NETNAME"          
          goodline = false if da_count > 10 or country_count > 4 or netname_count > 1 
          goodline = false if country_count > 1 and line[0] == "COUNTRY"                
          goodline = false if line[1][0] == "-"
          goodline = false if country_list.index(line[1])
          goodline = false if line[0] == "ADDRESS" and line[1] == country
          goodline = false if odd_list.index(line[1][0..4]) 
          goodline = false if addressflag and line[0] == "DESCR"
          goodline = false if line[1].length < 2
          goodline = false if darray.index(line[1])
          darray << line[1] if goodline and (line[0] == "DESCR" or line[0] == "ADDRESS")
          if goodline
            country_count = country_count + 1 if line[0] == "COUNTRY"
            da_count = da_count + 1 if line[0] == "DESCR" or line[0] == "ADDRESS"
          end                            
        else
          line[0] = current
          line[1] = ""
        end         
        lastname = line[0]  
        if goodline
          if name_list.index(line[0])
            newline = line[0] + ': ' + line[1]
            formatted_file.puts '+ ' + newline
            outstring = outstring + newline + "\n"
          else
#            formatted_file.puts '. ' + line[0] + ':: ' + line[1]         
          end
        else          
#          formatted_file.puts '- ' + line[0]
        end      
      end
#      formatted_file.puts '+ ' + country_count.to_s + ': ' + da_count.to_s
      return outstring         
    end
  end
      
end

