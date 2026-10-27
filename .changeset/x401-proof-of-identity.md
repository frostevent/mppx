---
'mppx': patch
---

Added `mppx/x401` and the `x401` option of `Mppx.create()` on the server and the client. A server route opts in with `x401: { scope }`: its `402` carries one `PROOF-REQUEST` entry per payment challenge, and its paid request must carry a `PROOF-RESPONSE`, verified before the payment is verified or settled and answered with 400 or 401 when missing or rejected. The client presents for the selected challenge and sends the `PROOF-RESPONSE` with the payment credential on the same retry.
