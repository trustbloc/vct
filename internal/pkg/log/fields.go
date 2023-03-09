/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log Fields.
const (
	FieldServiceName          = "service"
	FieldSize                 = "size"
	FieldBackoff              = "backoff"
	FieldServiceEndpoint      = "serviceEndpoint"
	FieldTreeID               = "treeID"
	FieldLeaf                 = "leaf"
	FieldStore                = "store"
	FieldCommand              = "command"
	FieldVerifiableCredential = "vc"
	FieldSignature            = "signature"
	FieldTimestamp            = "timestamp"
	FieldPublicKey            = "publicKey"
)

// WithServiceName sets the service field.
func WithServiceName(value string) zap.Field {
	return zap.String(FieldServiceName, value)
}

// WithSize sets the size field.
func WithSize(value int) zap.Field {
	return zap.Int(FieldSize, value)
}

// WithBackoff sets the backoff field.
func WithBackoff(value time.Duration) zap.Field {
	return zap.Duration(FieldBackoff, value)
}

// WithServiceEndpoint sets the service-endpoint field.
func WithServiceEndpoint(value string) zap.Field {
	return zap.String(FieldServiceEndpoint, value)
}

// WithTreeID sets the service-endpoint field.
func WithTreeID(value int64) zap.Field {
	return zap.Int64(FieldTreeID, value)
}

// WithLeaf sets the leaf field.
func WithLeaf(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldLeaf, value))
}

// WithStore sets the store field.
func WithStore(value string) zap.Field {
	return zap.String(FieldStore, value)
}

// WithCommand sets the command field.
func WithCommand(value string) zap.Field {
	return zap.String(FieldCommand, value)
}

// WithVerifiableCredential sets the vc field.
func WithVerifiableCredential(value []byte) zap.Field {
	return zap.String(FieldVerifiableCredential, string(value))
}

// WithSignature sets the signature field.
func WithSignature(value []byte) zap.Field {
	return zap.ByteString(FieldSignature, value)
}

// WithTimestamp sets the timestamp field.
func WithTimestamp(value uint64) zap.Field {
	return zap.Uint64(FieldTimestamp, value)
}

// WithPublicKey sets the timestamp field.
func WithPublicKey(value interface{}) zap.Field {
	return zap.Inline(NewObjectMarshaller(FieldPublicKey, value))
}

// ObjectMarshaller uses reflection to marshal an object's fields.
type ObjectMarshaller struct {
	key string
	obj interface{}
}

// NewObjectMarshaller returns a new ObjectMarshaller.
func NewObjectMarshaller(key string, obj interface{}) *ObjectMarshaller {
	return &ObjectMarshaller{key: key, obj: obj}
}

// MarshalLogObject marshals the object's fields.
func (m *ObjectMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	return e.AddReflected(m.key, m.obj)
}
