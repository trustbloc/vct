/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package schema

import _ "embed" // loads SQL

//go:embed storage.sql
// SQL schema.
var SQL []byte // nolint: gochecknoglobals
