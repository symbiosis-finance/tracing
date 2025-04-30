package tracing

import (
	"fmt"
	"os"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

const ChainIDKey = attribute.Key("chain.id")

func ChainID(chainID int64) attribute.KeyValue {
	return ChainIDKey.Int64(chainID)
}

const ChainNameKey = attribute.Key("chain.name")

func ChainName(chainName string) attribute.KeyValue {
	return ChainNameKey.String(chainName)
}

const BlockNumberKey = attribute.Key("chain.block_number")

func BlockNumber(blockNumber uint64) attribute.KeyValue {
	return BlockNumberKey.Int64(int64(blockNumber))
}

const BlockHashKey = attribute.Key("chain.block_hash")

func BlockHash(blockHash fmt.Stringer) attribute.KeyValue {
	return BlockHashKey.String(blockHash.String())
}

const TransactionIDKey = attribute.Key("chain.transaction_id")

func TransactionID(txID fmt.Stringer) attribute.KeyValue {
	return TransactionIDKey.String(txID.String())
}

// Log index in block
const LogIndexKey = attribute.Key("chain.log_index")

func LogIndex(index uint) attribute.KeyValue {
	return TransactionIDKey.Int(int(index))
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

func AppEnvFromEnv() attribute.KeyValue {
	return AttributeFromEnv(semconv.ServiceNamespaceKey, "APP_ENV")
}

func ServiceNameFromEnv() attribute.KeyValue {
	return AttributeFromEnv(semconv.ServiceNameKey, "SERVICE")
}
