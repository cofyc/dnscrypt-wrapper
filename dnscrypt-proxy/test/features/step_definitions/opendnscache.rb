
require 'net/dns/resolver'

Given /^a working opendnscache on (\d+\.\d+\.\d+\.\d+)$/ do |resolver|
  resolver = Net::DNS::Resolver.new(nameserver: resolver)
  
  answer_section = resolver.query('resolver1.opendns.com', Net::DNS::A).answer
  answer_section.first.address.to_s.should eq('208.67.222.222')
  
  answer_section = resolver.query('resolver2.opendns.com', Net::DNS::A).answer
  answer_section.first.address.to_s.should eq('208.67.220.220')

  answer_section = resolver.query('debug.opendns.com', Net::DNS::TXT).answer
  answer_section.should_not be_empty
end

