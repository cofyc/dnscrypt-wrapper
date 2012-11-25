Feature: Small UDP query

  A query that fits in a small UDP packet.
  
  Scenario: query an existing name.
  
    Given a working opendnscache on 208.67.220.220
    And a running dnscrypt proxy with options "--edns-payload-size=0"
    When a client asks dnscrypt-proxy for "resolver1.opendns.com"
    Then dnscrypt-proxy returns "208.67.222.222"

  Scenario: query a nonexistent name.
  
    Given a working opendnscache on 208.67.220.220
    And a running dnscrypt proxy with options "--edns-payload-size=0"
    When a client asks dnscrypt-proxy for "nonexistent.opendns.com"
    Then dnscrypt-proxy returns a NXDOMAIN answer
