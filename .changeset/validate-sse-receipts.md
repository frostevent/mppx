---
'mppx': patch
---

Fixed `mppx validate` failing Tempo session responses that stream over SSE: when the receipt arrives in the event stream instead of the `Payment-Receipt` header, validation no longer requires the header.
