/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package canonicalizer

import (
	"encoding/json"

	"github.com/trustbloc/vct/internal/pkg/jsoncanonicalizer"
)

// MarshalCanonical marshals the given object into a canonicalized form
// (using JCS RFC canonicalization).
func MarshalCanonical(value interface{}) ([]byte, error) {
	valueBytes, ok := value.([]byte)

	if !ok {
		var err error

		valueBytes, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}

	return jsoncanonicalizer.Transform(valueBytes)
}
