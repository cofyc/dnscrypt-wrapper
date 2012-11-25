Feature: See if hostip can resolve names given a specific resolver

  Resolve names with the hostip utility using Google DNS.
  
  Scenario: resolve resolver1.opendns.com
  
    When I run `hostip -r 8.8.8.8 resolver1.opendns.com`
    Then the output should contain exactly:
    """
    208.67.222.222

    """
    And the exit status should be 0

  Scenario: resolve IPv6 address for www.opendns.com
  
    When I run `hostip -r 8.8.8.8 -6 www.opendns.com`
    Then the output should contain exactly:
    """
    2620:0:cc1:115::210

    """
    And the exit status should be 0

  Scenario: resolve a nonexistent name
  
    When I run `hostip -r 8.8.8.8 nonexistent.local`
    Then the output should contain exactly:
    """
    [name does not exist]

    """
    And the exit status should be 1

  Scenario: resolve a nonexistent IPv6 name
  
    When I run `hostip -r 8.8.8.8 -6 nonexistent.local`
    Then the output should contain exactly:
    """
    [name does not exist]

    """
    And the exit status should be 1
