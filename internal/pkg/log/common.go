/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import "go.uber.org/zap"

// WriteResponseBodyError outputs a 'write response body' error log to the given logger.
func WriteResponseBodyError(log *Log, err error) {
	log.WithOptions(zap.AddCallerSkip(1)).Error("Error writing response body", WithError(err))
}
