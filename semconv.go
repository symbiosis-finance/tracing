package tracing

import (
	"fmt"
	"os"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

// Attribute keys for blockchain semantic conventions shared across services.
const (
	ChainIDKey       = attribute.Key("chain.id")
	ChainNameKey     = attribute.Key("chain.name")
	BlockNumberKey   = attribute.Key("chain.block_number")
	BlockHashKey     = attribute.Key("chain.block_hash")
	TransactionIDKey = attribute.Key("chain.transaction_id")
	LogIndexKey      = attribute.Key("chain.log_index") // log index in block
)

// ChainID returns a chain.id attribute.
func ChainID(chainID int64) attribute.KeyValue {
	return ChainIDKey.Int64(chainID)
}

// ChainName returns a chain.name attribute.
func ChainName(chainName string) attribute.KeyValue {
	return ChainNameKey.String(chainName)
}

// BlockNumber returns a chain.block_number attribute.
func BlockNumber(blockNumber uint64) attribute.KeyValue {
	return BlockNumberKey.Int64(int64(blockNumber))
}

// BlockHash returns a chain.block_hash attribute.
func BlockHash(blockHash fmt.Stringer) attribute.KeyValue {
	return BlockHashKey.String(blockHash.String())
}

// TransactionID returns a chain.transaction_id attribute.
func TransactionID(txID fmt.Stringer) attribute.KeyValue {
	return TransactionIDKey.String(txID.String())
}

// LogIndex returns a chain.log_index attribute (log index within the block).
func LogIndex(index uint) attribute.KeyValue {
	return LogIndexKey.Int(int(index))
}

// AttributeFromEnv returns a string attribute with the environment variable's
// value, or an invalid (skipped) attribute if the variable is not set.
func AttributeFromEnv(key attribute.Key, envVar string) (attr attribute.KeyValue) {
	if value, ok := os.LookupEnv(envVar); ok {
		attr = key.String(value)
	}
	return
}

// MonikerKey is the attribute key naming a specific instance of a service
// (e.g. a validator or relayer node).
const MonikerKey = attribute.Key("moniker")

// Moniker returns a moniker attribute.
func Moniker(moniker string) attribute.KeyValue {
	return MonikerKey.String(moniker)
}

// MonikerAttrFromEnv returns the moniker attribute from the MONIKER
// environment variable, invalid (skipped) if unset.
func MonikerAttrFromEnv() attribute.KeyValue {
	return AttributeFromEnv(MonikerKey, "MONIKER")
}

// RequestIDKey is the attribute key carrying a request identifier.
const RequestIDKey = attribute.Key("request.id")

// RequestID returns a request.id attribute.
func RequestID(id string) attribute.KeyValue {
	return RequestIDKey.String(id)
}

// AppEnvFromEnv returns the service.namespace attribute from the APP_ENV
// environment variable, invalid (skipped) if unset.
func AppEnvFromEnv() attribute.KeyValue {
	return AttributeFromEnv(semconv.ServiceNamespaceKey, "APP_ENV")
}

// ServiceNameFromEnv returns the service.name attribute from the SERVICE
// environment variable, invalid (skipped) if unset.
func ServiceNameFromEnv() attribute.KeyValue {
	return AttributeFromEnv(semconv.ServiceNameKey, "SERVICE")
}
