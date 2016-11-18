Feature: Test certs in TXT records

  Test if dnscrypt-wrapper returns the certificate in TXT records

  Scenario: query provider-name, TXT record
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys1/1.cert"
    Then dnscrypt-wrapper does not returns "keys2/1.cert"

  Scenario: query provider-name, TXT record, multiple certificates
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert,keys2/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys1/1.cert"
    Then dnscrypt-wrapper returns "keys2/1.cert"

  Scenario: query provider-name, TXT record, multiple certificates and TCP resolver
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert,keys2/1.cert"
    And a tcp resolver
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys1/1.cert"
    Then dnscrypt-wrapper returns "keys2/1.cert"

  Scenario: query provider-name, A record
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "A" record
    Then a "Timeout::Error" is thrown

  Scenario: query non provider-name, TXT record
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert"
    When a client asks dnscrypt-wrapper for "not2.dnscrypt-cert.example.com" "TXT" record
    Then a "Timeout::Error" is thrown
