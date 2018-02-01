
require 'net/dns'
require 'net/dns/resolver'

WRAPPER_IP = '127.0.0.1'
WRAPPER_PORT = 5443

Before do
  @resolver = Net::DNS::Resolver.new(nameserver: WRAPPER_IP, port: WRAPPER_PORT)
end

After do
  Process.kill("KILL", @pipe.pid) if @pipe
  @pipe = nil
end

Around do |scenario, block|
  Timeout.timeout(3.0) do
    block.call
  end
end

Given /^a running dnscrypt wrapper with options "([^"]*)"$/ do |options|
  str = "../dnscrypt-wrapper " +
    "--resolver-address=127.0.0.1:53 " +
    "--provider-name=2.dnscrypt-cert.example.com " +
    "--listen-address=#{WRAPPER_IP}:#{WRAPPER_PORT} #{options}"
  @pipe = IO.popen(str.split, "r")
  begin
    Timeout.timeout(0.5) do
      Process.wait @pipe.pid
      @error = @pipe.read
      @pipe = nil
    end
  rescue Timeout::Error
    # The process is still running, so it did not fail yet/
  end
end

And /^a tcp resolver$/ do
  @resolver.use_tcp = true
end

When /^a client asks dnscrypt\-wrapper for "([^"]*)" "([^"]*)" record$/ do |name, qtype|
  begin
    Timeout.timeout(0.5) do
      @answer_section = @resolver.query(name, Net::DNS.const_get(qtype.upcase)).answer
    end
  rescue Timeout::Error => @error
  rescue Errno::ECONNREFUSED => @error
  end
end

Then /^dnscrypt\-wrapper returns "([^"]*)"$/ do |certfile|
  cert = open(certfile).read()
  expect(@answer_section.collect { |a| a.txt.strip().force_encoding('UTF-8') }).to include(cert)
end

Then /^dnscrypt-wrapper fails with "(.*)"$/ do |error|
  expect(@error).to include(error)
end

Then /^dnscrypt\-wrapper does not return "([^"]*)"$/ do |certfile|
  cert = open(certfile).read()
  expect(@answer_section.collect { |a| a.txt.strip().force_encoding('UTF-8') }).not_to include(cert)
end

Then /^a "(.*)" is thrown$/ do |error|
  @error.class.to_s == error
end
