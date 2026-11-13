/** x401 values. */
export const Constants = {
  /** Identity type advertised in the 402's `Identity-Required` header. */
  type: 'x401',
  /** Response header of a 402 that carries the proof request. */
  requestHeader: 'PROOF-REQUEST',
  /** Request header of the paid retry that carries the proof. */
  responseHeader: 'PROOF-RESPONSE',
  /** Response header of a rejection that carries the x401 error. */
  resultHeader: 'PROOF-RESULT',
} as const
