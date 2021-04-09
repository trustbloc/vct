#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
Feature: Verifiable credentials transparency API.
  Scenario: Adds verifiable credentials to Log
    Given VCT agent is running on "http://localhost:56565"
    Then  Add verifiable credential "bachelor_degree.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"
    And   Retrieve entries from log and check that len is "1"

  Scenario: Adds verifiable credentials to Log (duplicate)
    Given VCT agent is running on "http://localhost:56565"
    Then  Add verifiable credential "verifiable_credentials_bbs+.json" to Log
    And   Add verifiable credential "verifiable_credentials_bbs+.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"
    And   Retrieve entries from log and check that len is "1"

  Scenario: Retrieve merkle consistency proof between signed tree heads
    Given VCT agent is running on "http://localhost:56565"
    Then  Add verifiable credential "bachelor_degree_of_arts_no_proof.json" to Log
    And   Add verifiable credential "bachelor_degree_of_science_no_proof.json" to Log
    And   Add verifiable credential "verifiable_credentials_no_proof.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "3"
    Then  Retrieve merkle consistency proof between signed tree heads

  Scenario: Retrieve merkle audit proof from log by leaf hash
    Given VCT agent is running on "http://localhost:56565"
    Then  Add verifiable credential "bachelor_degree_of_finance_no_proof.json" to Log
    And   Add verifiable credential "bachelor_degree_of_law_no_proof.json" to Log
    And   Retrieve entries from log and check that len is "2"
    And   Retrieve merkle audit proof from log by leaf hash for "bachelor_degree_of_finance_no_proof.json"
    And   Retrieve merkle audit proof from log by leaf hash for "bachelor_degree_of_law_no_proof.json"
