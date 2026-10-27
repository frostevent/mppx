---
'mppx': patch
---

Added optional `summary` and `requestBody` to proxy endpoint definitions (`{ pay, options, summary, requestBody }`), emitted in the proxy's generated `/openapi.json`. Endpoint objects without `pay` are now free passthrough routes.
