import type * as Challenge from '../Challenge.js'
import type * as Errors from '../Errors.js'

/**
 * One Digital Credentials API request entry, for example
 * `{ protocol: 'openid4vp-v1-signed', data: { request: '<JAR>' } }`.
 */
export type Requirement = {
  /** Digital Credentials API protocol identifier. */
  protocol: string
  /** Protocol-specific request, opaque to mppx. */
  data: unknown
}

/** A wallet's answer to a {@link Requirement}: the credential result data itself, or a URL the server fetches it from. */
export type Presentation =
  | {
      /** Protocol-specific credential result data, opaque to mppx. */
      data: unknown
    }
  | {
      /** HTTPS URL returning the credential result `{ protocol, data }`. */
      resultUri: string
      /** RFC 3339 time after which `resultUri` is no longer valid. */
      expiresAt?: string | undefined
    }

/** Outcome of verifying a presentation. */
export type Verified<value> =
  | {
      /**
       * Id of the payment challenge each credential of the presentation is bound to, or
       * `undefined` for a credential that carries no binding. mppx accepts the presentation
       * only when the list is non-empty and every entry is the paid challenge's id.
       */
      challengeIds: readonly (string | undefined)[]
      /** Verified data, returned to the route as `result.x401`. */
      value: value
    }
  | {
      /** Short ASCII x401 error code, for example `invalid_result` or `invalid_nonce`. */
      error: string
      /** Human-readable diagnostic text. Never include the presentation itself. */
      error_description?: string | undefined
    }

/** Names of the x401 HTTP headers, as `HEADER` of `@proof.com/x401-node` defines them. */
export type Headers = {
  readonly PROOF_REQUEST: string
  readonly PROOF_RESPONSE: string
  readonly PROOF_RESULT: string
}

/** Server side of x401 as `mppx/server` calls it. Create one with `x401.Server.verifier()`. */
export type Verifier = {
  /** Names of the x401 HTTP headers. */
  headers: Headers
  /** Returns the encoded `PROOF-REQUEST` entry for one payment challenge. */
  proofRequest: (parameters: { challenge: Challenge.Challenge; scope: string }) => Promise<string>
  /** Verifies the encoded `PROOF-RESPONSE` sent with a credential for `challenge`. */
  verifyProof: (parameters: {
    challenge: Challenge.Challenge
    proofResponse: string
  }) => Promise<{ value: unknown } | { error: Errors.ProofRejectedError }>
}

/** Client side of x401 as `mppx/client` calls it. Create one with `x401.Client.wallet()`. */
export type Wallet = {
  /** Names of the x401 HTTP headers. */
  headers: Headers
  /**
   * Returns the encoded `PROOF-RESPONSE` for `challenge`, or `undefined` when the
   * `PROOF-REQUEST` carries no entry for it.
   */
  proofResponse: (parameters: {
    challenge: Challenge.Challenge
    origin: string
    proofRequest: string
  }) => Promise<string | undefined>
}
