require 'rubygems'
require 'rake/gempackagetask'
require 'rake/rdoctask'
require 'rake/testtask'

spec = Gem::Specification.new do |s|
    s.name      =   "vizi_whois"
    s.version   =   "0.1.0"
    s.author    =   "Al Kivi"
    s.email     =   "al.kivi at vizitrax.com"
    s.homepage  =   "http://github.com/al-kivi/Vizi_Whois"
    s.summary = "Global whois module to select the right whois server and get response data"
    s.description = "This gem module provides a classes to find the right Regional Internet Registry
      for a given IP Address. The query method will navigate each major RIR until a response is found"
    
    s.platform  =   Gem::Platform::RUBY
    s.has_rdoc  =   true
    s.extra_rdoc_files  =   ["README.rdoc"]

    s.require_path  =   "lib"
    s.files     =   %w(README.rdoc Rakefile) + Dir.glob("lib/**/*")
end

Rake::GemPackageTask.new(spec) do |pkg|
    pkg.need_tar = true
end

Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'HttpLogParser'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList["test/**/*_test.rb"]
  t.verbose = true
end

task :default => "pkg/#{spec.name}-#{spec.version}.gem" do
    puts "generated latest version"
end

