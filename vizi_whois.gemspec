require 'rubygems'

spec = Gem::Specification.new do |s|
  s.name = 'vizi_whois'
  s.version = '0.1.0'
  s.summary = "Global whois capability to select the right whois server and get response data"
  s.description = "This gem module provides a classes to find the right Regional Internet Registry
    for a given IP Address. The query method will navigate each major RIR until a response is found.
    
    A second class allows the responses from various RIRs to be formatted to a common response format"
  s.files = Dir.glob("**/**/**")
  s.test_files = Dir.glob("test/*_test.rb")
  s.author = "Al Kivi"
  s.homepage = "http://www.vizitrax.com"
  s.email = "al.kivi@vizitrax.com"
  s.has_rdoc = true
  s.required_ruby_version = '>= 1.8.2'
end
