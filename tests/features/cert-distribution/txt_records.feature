Feature: Test certs in TXT records

  Test if dnscrypt-wrapper returns the certificate in TXT records

  Scenario: query provider-name, TXT record
    """
    check that we can serve 1 cert.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys1/1.cert"
    Then dnscrypt-wrapper does not returns "keys2/1.cert"

  Scenario: query provider-name, TXT record, multiple certificates
    """
    check that we can serve multiple certs.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert,keys2/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys1/1.cert"
    Then dnscrypt-wrapper returns "keys2/1.cert"

  Scenario: query provider-name, TXT record, multiple esversion same key
    """
    Check that we can serve multiple certs with different ES versions
    for the same key.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys2/1.key  --provider-cert-file=keys2/1.cert,keys2/1.xchacha20.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys2/1.cert"
    Then dnscrypt-wrapper returns "keys2/1.xchacha20.cert"

  Scenario: query provider-name, TXT record, key with no cert
    """
    when a key is provided but we don't have matching cert, dnscrypt-wrapper
    should fail to start.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys2/2.key  --provider-cert-file=keys2/1.cert,keys2/1.xchacha20.cert"
    Then dnscrypt-wrapper fails with "could not match secret key 1 with a certificate"

  Scenario: query provider-name, TXT record, multiple certificates and TCP resolver
    """
    check that we can serve certs over TCP.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert,keys2/1.cert"
    And a tcp resolver
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "TXT" record
    Then dnscrypt-wrapper returns "keys1/1.cert"
    Then dnscrypt-wrapper returns "keys2/1.cert"

  Scenario: query provider-name, A record
    """
    Check that A records are not served unencrypted.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert"
    When a client asks dnscrypt-wrapper for "2.dnscrypt-cert.example.com" "A" record
    Then a "Timeout::Error" is thrown

  Scenario: query non provider-name, TXT record
    """
    Check that TXT record for something else than provider name are not served
    unencrypted.
    """
    Given a running dnscrypt wrapper with options "--crypt-secretkey-file=keys1/1.key  --provider-cert-file=keys1/1.cert"
    When a client asks dnscrypt-wrapper for "not2.dnscrypt-cert.example.com" "TXT" record
    Then a "Timeout::Error" is thrown
