#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
Feature: Verifiable credentials transparency API.
  Scenario: Adds verifiable credentials to Log
    Given VCT agent with ledger "https://vct.example.com/maple2021" is running on "http://localhost:5678/maple2021"
    Then  Add verifiable credential "maple2021/bachelor_degree_no_proof.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"
    And   Retrieve entries from log and check that len is "1"

  Scenario: Adds verifiable credentials to Log (duplicate)
    Given VCT agent with ledger "https://vct.example.com/maple2021" is running on "http://localhost:5678/maple2021"
    Then  Add verifiable credential "maple2021/verifiable_credentials_bbs+.json" to Log
    And   Add verifiable credential "maple2021/verifiable_credentials_bbs+.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"
    And   Retrieve entries from log and check that len is "1"
    Then  Use timestamp from "maple2021/verifiable_credentials_bbs+.json" for "maple2021/verifiable_credentials_bbs+_no_proof.json"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2021/verifiable_credentials_bbs+_no_proof.json"

  Scenario: Retrieve merkle consistency proof between signed tree heads
    Given VCT agent with ledger "https://vct.example.com/maple2021" is running on "http://localhost:5678/maple2021"
    Then  Add verifiable credential "maple2021/bachelor_degree_of_arts_no_proof.json" to Log
    And   Add verifiable credential "maple2021/bachelor_degree_of_science_no_proof.json" to Log
    And   Add verifiable credential "maple2021/verifiable_credentials_no_proof.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "3"
    Then  Retrieve merkle consistency proof between signed tree heads

  Scenario: Retrieve merkle audit proof from log by leaf hash
    Given VCT agent with ledger "https://vct.example.com/maple2021" is running on "http://localhost:5678/maple2021"
    Then  Add verifiable credential "maple2021/bachelor_degree_of_finance_no_proof.json" to Log
    And   Add verifiable credential "maple2021/bachelor_degree_of_law_no_proof.json" to Log
    And   Retrieve entries from log and check that len is "2"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2021/bachelor_degree_of_finance_no_proof.json"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2021/bachelor_degree_of_law_no_proof.json"

  Scenario: Retrieve merkle audit proof from log by leaf hash (did web)
    Given VCT agent with ledger "https://vct.example.com/maple2021" is running on "http://localhost:5678/maple2021"
    Then  Add verifiable credential "maple2021/bachelor_degree_web_proof.json" to Log
    And   Retrieve entries from log and check that len is "1"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2021/bachelor_degree_web_proof.json"

  Scenario: Adds verifiable credentials to Log
    Given VCT agent with ledger "https://vct.example.com/maple2020" is running on "http://localhost:5678/maple2020"
    Then  Add verifiable credential "maple2020/bachelor_degree_no_proof.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"
    And   Retrieve entries from log and check that len is "1"

  Scenario: Adds verifiable credentials to Log (duplicate)
    Given VCT agent with ledger "https://vct.example.com/maple2020" is running on "http://localhost:5678/maple2020"
    Then  Add verifiable credential "maple2020/verifiable_credentials_bbs+.json" to Log
    And   Add verifiable credential "maple2020/verifiable_credentials_bbs+.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "1"
    And   Retrieve entries from log and check that len is "1"
    Then  Use timestamp from "maple2020/verifiable_credentials_bbs+.json" for "maple2020/verifiable_credentials_bbs+_no_proof.json"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2020/verifiable_credentials_bbs+_no_proof.json"

  Scenario: Retrieve merkle consistency proof between signed tree heads
    Given VCT agent with ledger "https://vct.example.com/maple2020" is running on "http://localhost:5678/maple2020"
    Then  Add verifiable credential "maple2020/bachelor_degree_of_arts_no_proof.json" to Log
    And   Add verifiable credential "maple2020/bachelor_degree_of_science_no_proof.json" to Log
    And   Add verifiable credential "maple2020/verifiable_credentials_no_proof.json" to Log
    When  Retrieve latest signed tree head and check that tree_size is "3"
    Then  Retrieve merkle consistency proof between signed tree heads

  Scenario: Retrieve merkle audit proof from log by leaf hash
    Given VCT agent with ledger "https://vct.example.com/maple2020" is running on "http://localhost:5678/maple2020"
    Then  Add verifiable credential "maple2020/bachelor_degree_of_finance_no_proof.json" to Log
    And   Add verifiable credential "maple2020/bachelor_degree_of_law_no_proof.json" to Log
    And   Retrieve entries from log and check that len is "2"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2020/bachelor_degree_of_finance_no_proof.json"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2020/bachelor_degree_of_law_no_proof.json"

  Scenario: Retrieve merkle audit proof from log by leaf hash (did web)
    Given VCT agent with ledger "https://vct.example.com/maple2020" is running on "http://localhost:5678/maple2020"
    Then  Add verifiable credential "maple2020/bachelor_degree_web_no_proof.json" to Log
    And   Retrieve entries from log and check that len is "1"
    And   Retrieve merkle audit proof from log by leaf hash for "maple2020/bachelor_degree_web_no_proof.json"

  Scenario: Checks issuers
    Given VCT agent with ledger "https://vct.example.com/maple2020" is running on "http://localhost:5678/maple2020"
    Then The issuer "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N7" is supported
    And  The issuer "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2" is not supported

    Given VCT agent with ledger "https://vct.example.com/maple2021" is running on "http://localhost:5678/maple2021"
    Then The issuer "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2" is supported
    And  The issuer "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N7" is not supported

    Given VCT agent with ledger "https://vct.example.com/maple2022" is running on "http://localhost:5678/maple2022"
    Then The issuer "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2" is supported
    And  The issuer "did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N7" is supported

  Scenario: Checks permissions
    Given VCT agent with ledger "https://vct.example.com/maple2022" is running on "http://localhost:5678/maple2022"
    Then  No permissions to write

    Given VCT agent with ledger "https://vct.example.com/maple2023" is running on "http://localhost:5678/maple2023"
    Then  No permissions to read
