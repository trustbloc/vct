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

  Scenario: Adds verifiable credentials to Log (duplicate)
    Given VCT agent is running on "http://localhost:56565"
    Then  Add verifiable credential "verifiable_credentials_bbs+.json" to Log
    And   Add verifiable credential "verifiable_credentials_bbs+.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"