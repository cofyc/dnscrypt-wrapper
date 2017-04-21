Feature: Test that certificates can be properly generated.

  Tests if dnscrypt-wrapper can properly generate certificates

  Scenario: Generate a xsalsa20 cert
    Given a provider keypair
    And a time limited secret key
    When a xsalsa20 cert is generated
    Then it is a xsalsa20 cert

  Scenario: Generate a xchacha20 cert
    Given a provider keypair
    And a time limited secret key
    When a xchacha20 cert is generated
    Then it is a xchacha20 cert
