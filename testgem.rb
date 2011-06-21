# This is a sample application that uses the Vizi_whois gem classes
# 
# This application will read a text file with IP addresses.
# For each IP address, the whois method will be called and responses received.
#
# Author::    Al Kivi <al.kivi@vizitrax.com>

## require 'c:\rails\vizi_whois\lib\vizi_whois'
require 'vizi_whois'

require 'logger'
require 'socket'
 
syslog = Logger.new('./log/system.log',shift_age = 'weekly')
syslog.info "Starting IP address test file ... >>> "+Time.now.to_s

out_file = File.new('./log/output.log', 'w')

File.delete('./log/formatted.log') if File.exist?('./log/formatted.log') 
parse_file = File.new('./log/formatted.log', 'w')

# Open test file for reading
File.open('./data/testfile.txt', 'r') do |file|
  rec_count = 0
  while(line = file.gets) # Read each line of the test file, one IP address per line
    @whoisresult = Vizi::Gowhois.new
    p line.chomp
    rarray = @whoisresult.query(line.chomp)
    @contents = rarray[0]
    out_file.puts '----------------------------------------------------------------'
    out_file.puts '> ' + line 
    out_file.puts '>> ' + rarray[1]
    out_file.puts '>>> ' + rarray[2]     
    out_file.puts '----------------------------------------------------------------'    
    out_file.puts @contents
    @result = Vizi::Formatter.new
    @formatted = @result.parse(@contents, rarray[1], rarray[2]) 
    p @formatted   
    rec_count = rec_count + 1 
  end
  syslog.info "Record count is "+rec_count.to_s
  syslog.info "Ending ... >>> "+Time.now.to_s
end

