import {
  HEADER,
  verifier as x401,
  type DigitalCredentialRequestEntry,
  type ResultArtifact,
} from '@proof.com/x401-node'

import type * as Challenge from '../Challenge.js'
import * as Errors from '../Errors.js'
import type { MaybePromise } from '../internal/types.js'
import type * as Types from './Types.js'

const credentialResultTimeoutMs = 5_000
const paymentSchemeHint = 'mpp/draft-httpauth-payment-00'

/**
 * Creates the x401 Verifier passed as `x401` to `Mppx.create()` from `mppx/server`.
 *
 * A route opts in with `x401: { scope }` in its handler options. Each Payment challenge of its
 * `402` gets its own `PROOF-REQUEST` entry built from `request`, whose `payment.notes` is the
 * challenge id. On the paid retry, mppx reads the credential result `data` from the
 * `PROOF-RESPONSE` (fetching `credential_result_uri` when the wallet sent one) and calls
 * `verify` before the payment is verified or settled. `verify` returns the challenge id each
 * credential is bound to; mppx accepts only when every one is the paid challenge's id, and the
 * route reads the verified `value` as `result.x401`. A throw from `verify` propagates.
 *
 * @example
 * ```ts
 * import { Mppx, tempo } from 'mppx/server'
 * import * as x401 from 'mppx/x401'
 *
 * const mppx = Mppx.create({
 *   secretKey,
 *   methods: [tempo()],
 *   x401: x401.Server.verifier({
 *     request: ({ challenge, scope }) => requirementFor(challenge, scope),
 *     verify: ({ challenge, data }) => verifyPresentation(challenge, data),
 *   }),
 * })
 *
 * const result = await mppx.charge({ amount: '0.01', x401: { scope } })(request)
 * ```
 */
export function verifier<value>(config: verifier.Config<value>): Types.Verifier {
  return {
    headers: HEADER,
    async proofRequest({ challenge, scope }) {
      const requirement = await config.request({ challenge, scope })
      return x401.encodePayload(
        x401.buildPayload({
          credentialRequirements: {
            digital: { requests: [requirement as DigitalCredentialRequestEntry] },
          },
          payment: { required: true, scheme_hint: paymentSchemeHint, notes: challenge.id },
        }),
      )
    },
    async verifyProof({ challenge, proofResponse }) {
      let data: unknown
      try {
        data = await credentialResultDataOf(proofResponse)
      } catch (cause) {
        return rejected(400, {
          cause,
          error: 'invalid_response',
          error_description:
            'PROOF-RESPONSE is malformed or its credential result could not be fetched',
        })
      }
      const verified = await config.verify({ challenge, data })
      if ('error' in verified) return rejected(401, verified)
      const { challengeIds } = verified
      if (challengeIds.length === 0 || challengeIds.some((id) => id !== challenge.id))
        return rejected(401, {
          error: 'invalid_result',
          error_description: 'The presentation is not bound to this payment challenge',
        })
      return { value: verified.value }
    },
  }
}

async function credentialResultDataOf(proofResponse: string): Promise<unknown> {
  const artifact = x401.decodeResultArtifact(proofResponse)
  const result =
    artifact.credential_result_uri === undefined
      ? artifact.credential_result
      : await fetchCredentialResult(artifact)
  if (typeof result !== 'object' || result === null || !('data' in result))
    throw new Error('The credential result carries no data.')
  return result.data
}

async function fetchCredentialResult(artifact: ResultArtifact): Promise<unknown> {
  if (artifact.expires_at !== undefined && !(Date.parse(artifact.expires_at) > Date.now()))
    throw new Error(`credential_result_uri expired at ${artifact.expires_at}.`)
  const response = await fetch(artifact.credential_result_uri!, {
    signal: AbortSignal.timeout(credentialResultTimeoutMs),
  })
  if (!response.ok) throw new Error(`credential_result_uri answered HTTP ${response.status}.`)
  return response.json()
}

function rejected(
  status: 400 | 401,
  parameters: { cause?: unknown; error: string; error_description?: string | undefined },
): { error: Errors.ProofRejectedError } {
  const { cause, error, error_description } = parameters
  return {
    error: new Errors.ProofRejectedError({
      ...(cause !== undefined && { cause }),
      reason: error_description ?? error,
      result: x401.encodeErrorObject(
        x401.buildErrorObject({
          error,
          ...(error_description !== undefined && { error_description }),
        }),
      ),
      status,
    }),
  }
}

export declare namespace verifier {
  type Config<value> = {
    /** Returns the Digital Credentials API request entry for one payment challenge. */
    request: (parameters: {
      /** The payment challenge the presentation must be bound to. */
      challenge: Challenge.Challenge
      /** The route's `x401.scope`. */
      scope: string
    }) => MaybePromise<Types.Requirement>
    /**
     * Verifies the presentation sent with a credential for `challenge`. Returns `{ error }` for
     * a rejected presentation, and throws only when verification itself fails.
     */
    verify: (parameters: {
      /** The paid challenge, already checked as issued by this server and unexpired. */
      challenge: Challenge.Challenge
      /** The credential result `data`, opaque to mppx. */
      data: unknown
    }) => MaybePromise<Types.Verified<value>>
  }
}
