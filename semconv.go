package tracing

import (
	"fmt"
	"os"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

const (
	ChainIDKey       = attribute.Key("chain.id")
	ChainNameKey     = attribute.Key("chain.name")
	BlockNumberKey   = attribute.Key("chain.block_number")
	BlockHashKey     = attribute.Key("chain.block_hash")
	TransactionIDKey = attribute.Key("chain.transaction_id")
	LogIndexKey      = attribute.Key("chain.log_index") // log index in block
)

func ChainID(chainID int64) attribute.KeyValue {
	return ChainIDKey.Int64(chainID)
}

func ChainName(chainName string) attribute.KeyValue {
	return ChainNameKey.String(chainName)
}

func BlockNumber(blockNumber uint64) attribute.KeyValue {
	return BlockNumberKey.Int64(int64(blockNumber))
}

func BlockHash(blockHash fmt.Stringer) attribute.KeyValue {
	return BlockHashKey.String(blockHash.String())
}

func TransactionID(txID fmt.Stringer) attribute.KeyValue {
	return TransactionIDKey.String(txID.String())
}

func LogIndex(index uint) attribute.KeyValue {
	return LogIndexKey.Int(int(index))
}

func AttributeFromEnv(key attribute.Key, envVar string) (attr attribute.KeyValue) {
	if value, ok := os.LookupEnv(envVar); ok {
		attr = key.String(value)
	}
	return
}

const MonikerKey = attribute.Key("moniker")

func Moniker(moniker string) attribute.KeyValue {
	return MonikerKey.String(moniker)
}

func MonikerAttrFromEnv() attribute.KeyValue {
	return AttributeFromEnv(MonikerKey, "MONIKER")
}

const RequestIDKey = attribute.Key("request.id")

func RequestID(id fmt.Stringer) attribute.KeyValue {
	return RequestIDKey.String(id.String())
}

func AppEnvFromEnv() attribute.KeyValue {
	return AttributeFromEnv(semconv.ServiceNamespaceKey, "APP_ENV")
}

func ServiceNameFromEnv() attribute.KeyValue {
	return AttributeFromEnv(semconv.ServiceNameKey, "SERVICE")
}
