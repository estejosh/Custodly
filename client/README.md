# client/

Local client: wraps `keepassxc-cli` to read/write `working.kdbx` and
`master.kdbx`, exposes the request contract (`get me a key for provider X,
scoped to [...], expiring in [...]`) that n8n workflows call into. Not yet
built — blocked on device shell access to beastly; see ../docs/mvp-scope.md.
