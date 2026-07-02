# Attributes

The package ships typed attribute constructors so span attributes stay consistent across services.

## Web3 / blockchain conventions

| Constructor | Key | Type |
|---|---|---|
| `ChainID(int64)` | `chain.id` | int64 |
| `ChainName(string)` | `chain.name` | string |
| `BlockNumber(uint64)` | `chain.block_number` | int64 |
| `BlockHash(fmt.Stringer)` | `chain.block_hash` | string |
| `TransactionID(fmt.Stringer)` | `chain.transaction_id` | string |
| `LogIndex(uint)` | `chain.log_index` | int |

```go
ctx, span := tracing.StartSpan(ctx, "processEvent", trace.WithAttributes(
    tracing.ChainID(56),
    tracing.BlockNumber(event.BlockNumber),
    tracing.TransactionID(event.TxHash),
))
```

## Service identity

| Constructor | Key | Source |
|---|---|---|
| `Moniker(string)` / `MonikerAttrFromEnv()` | `moniker` | `MONIKER` env var |
| `ServiceNameFromEnv()` | `service.name` | `SERVICE` env var |
| `AppEnvFromEnv()` | `service.namespace` | `APP_ENV` env var |
| `VersionAttr()` | `service.version` | `Version` ldflags variable |
| `RequestID(string)` | `request.id` | your request handler |

`AttributeFromEnv(key, envVar)` is the generic building block: it returns a valid attribute only when the environment variable is set, and invalid attributes are skipped everywhere (resource construction, log fields).

## Generic helpers

- `ErrorAttr(key, err)` — string attribute from an error; invalid (skipped) when the error is nil.
- `NilStringer(name, stringer)` — like `attribute.Stringer` but safe for nil values (renders `<nil>` instead of panicking).
- `StringerSlice(key, values)` — string-slice attribute from any `[]T` where `T` implements `fmt.Stringer`.
- `Map` / `Map2` — small `iter.Seq` transformation helpers used internally, exported for convenience.
