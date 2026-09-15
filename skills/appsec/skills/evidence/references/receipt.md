# Controller receipt rules

Read and search only declared pinned repositories. The controller returns commit,
path, line range and full-file content hash. Do not fabricate source references or
attempt to send lease, generation, token or attempt identifiers as tool arguments.
The authenticated connection supplies those identities.

Use task-scoped idempotency keys for submissions. Retrying an unchanged submission
returns its original receipt. Reusing a key with changed content is an error.
Use upload evidence for bounded structured observations and stored evidence only
when the artifact actually exists. Attachments alone do not establish source truth.
