Feature: fallback to TCP

  A query that doesn't fit in a small UDP packet should make the proxy
send a truncated reply, then the stud resolver should retry with TCP
and the proxy should handle TCP just fine.
  
  Scenario: query an existing name over UDP, expect fallback to TCP.
  
    Given a working opendnscache on 208.67.220.220
    And a running dnscrypt proxy with options "--edns-payload-size=0"
    When a client asks dnscrypt-proxy for "test-tcp.stdc.org"
    Then dnscrypt-proxy returns "127.0.0.1"
