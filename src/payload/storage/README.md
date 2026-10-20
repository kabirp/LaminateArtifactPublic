# Trace-store implementation

This directory implements the persistent trace API declared by
[`file_trace_store.hpp`](../../../include/laminate/payload/storage/file_trace_store.hpp).
The public header owns typed backend adapters; these files own the
backend-independent byte store. The two subdirectories separate bytes on disk
from the lifetime of an admitted store.

## Reading the implementation

Start with [`store/writer.cpp`](store/writer.cpp) for publication, [`store/open.cpp`](store/open.cpp) for validation
of an existing artifact, and [`store/readers.cpp`](store/readers.cpp) for the sequential access
used during proving. Reclamation is a separate, irreversible lifecycle; it
must be considered when following a checkpoint through its final consumer.

- [`format/schema.cpp`](format/schema.cpp) defines the version-four constants, metadata
  primitives, enum encodings, and path rules.
- [`format/files.cpp`](format/files.cpp) binds reads and writes to validated operating-system
  file identities.
- [`format/layer_format.cpp`](format/layer_format.cpp) defines layer-record framing and rolling
  digests.
- [`format/manifest.cpp`](format/manifest.cpp) encodes and parses the immutable store
  manifest.
- [`format/layer_validation.cpp`](format/layer_validation.cpp) scans each layer once, validating every
  record and building its trusted offset index.
- [`format/retirement.cpp`](format/retirement.cpp) encodes the immutable retirement
  session and event chain.
- [`store/publication.cpp`](store/publication.cpp) publishes staged files atomically without
  replacing an existing path.
- [`store/descriptor.cpp`](store/descriptor.cpp) validates public trace metadata and its binding
  to a compiled payload circuit.
- [`store/writer.cpp`](store/writer.cpp) owns storage reservations, layer construction, and
  no-replace publication of layers and the final manifest. It also supports a
  consuming handoff from a same-process single-layer writer to its reader.
- [`store/private_alias.cpp`](store/private_alias.cpp) publishes an eligible same-process single-layer
  alias by hard link, with runtime ownership and last-link reclamation
  accounting. This optimization requires matching file geometry and does not
  create an independently restartable trace.
- [`store/open.cpp`](store/open.cpp) is the sole transition from untrusted files to a
  fully validated private store.
- [`store/readers.cpp`](store/readers.cpp) issues leased range readers only from that
  validated state.
- [`store/reclamation.cpp`](store/reclamation.cpp) owns destructive scratch removal and the live
  no-retry retirement state machine.
- [`store/retirement_journal.cpp`](store/retirement_journal.cpp) independently validates a persisted
  retirement event chain after interruption.

The headers under `format/` are narrow private contracts between format units.
[`store/validated_state.hpp`](store/validated_state.hpp) defines the shared private state admitted by checked
opening or a consuming same-writer handoff. Callers continue to include only
the public header.

## Integrity and lifetime

`ReopenableAuthenticated` is the default integrity mode. Persisted artifacts
enter through `open`, which validates manifest bindings, record framing,
digests, indexes, and the caller's typed record checks. The specialized
`SameProcessEphemeral` mode is confined to a consuming writer-to-reader
handoff. It preserves canonical records and file-identity checks while
omitting record hashes that will not be validated by a later process. It is
not a reopenable persistence mode.

Both modes require exclusive ownership of the backing directories. Manifest
checks and file identities do not authorize concurrent mutation by another
process. Reader leases and retirement state prevent removing files that still
have active consumers; failures after irreversible retirement begins are
terminal for the session.

Storage behavior is checked in
[`tests/payload/storage/`](../../../tests/payload/storage/), with replay
composition in
[`tests/payload/checkpoint/`](../../../tests/payload/checkpoint/).
