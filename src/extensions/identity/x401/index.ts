/**
 * x401 (https://x401.proof.com/spec/latest/) proofs of identity, bound to the payment Challenge
 * they are paid with: each Challenge of a 402 carries its own `PROOF-REQUEST`, and the paid
 * retry carries the `PROOF-RESPONSE`, which is verified before the payment settles.
 */

/** Client prover that answers the `PROOF-REQUEST` of the Challenge it pays. */
export * as Client from './client/index.js'
/** Server payment check that requires a proof bound to the paid Challenge. */
export * as Server from './server/index.js'
export * from './Constants.js'
export type * from './Types.js'
