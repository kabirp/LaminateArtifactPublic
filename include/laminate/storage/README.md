# Bounded proof-artifact storage

This module supplies the backend-independent storage primitives used by
external-memory proving. Ciphertext traces have a separate typed interface in
[`payload/storage/file_trace_store.hpp`](../payload/storage/file_trace_store.hpp),
and persistent client/server setup is in
[`protocol/storage/`](../protocol/storage/).

## Native-field artifacts

[`native_field_artifact.hpp`](native_field_artifact.hpp) stores named arrays
of `Fq`, `Fq2`, or BaseFold digests. Version 1 uses canonical fixed-width
element encodings, per-array metadata, integrity digests, and a final
manifest. `native_field_artifact_physical_bytes` computes the exact completed
file lengths before construction.

The writer requires an existing, empty, private directory and explicit total
byte and free-space limits. It publishes completed arrays before the manifest
and never selects a scratch location itself. This detects incomplete
publication; it does not promise power-loss durability through `fsync`.

Opening a persisted artifact performs a sequential integrity and canonical
encoding pass over every array. Typed readers then support bounded reads and
seeks in element units. `trusted_finished_artifact` is a narrower in-process
handoff from a completed writer; it assumes the private directory has remained
unchanged and does not replace validation of externally supplied files.

## External record sorting

[`external_record_sort.hpp`](external_record_sort.hpp) orders opaque records
by a public destination key while preserving append order for equal keys.
Caller-provided limits bound buffered records, payload bytes, live temporary
bytes, and merge fan-in. A shared `ExternalRecordSortBudget` can charge final
output bytes and overlapping temporary runs against one combined ceiling.

The sorter creates one owned child workspace. Successful completion removes
its runs; failure cleanup removes only files whose type and length still
match its ledger. Unrecognized or replaced paths are left in place. The
surrounding protocol owns the lifetime of final artifacts.

Both interfaces assume exclusive caller ownership of their directories while
in use. Their byte ledgers measure the specified files and buffers; allocator,
filesystem allocation, and metadata overhead must be budgeted by the caller.
Implementations are in [`src/storage/`](../../../src/storage/), and artifact
format checks are in [`tests/storage/`](../../../tests/storage/).
