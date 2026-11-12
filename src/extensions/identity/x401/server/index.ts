import * as Challenge from '../../../../Challenge.js'
import type * as Credential from '../../../../Credential.js'
import type * as Identity from '../../../../identity/Types.js'
import type { MaybePromise } from '../../../../internal/types.js'
import { Constants } from '../Constants.js'
import type { CredentialRequest } from '../Types.js'

/**
 * Creates a payment check that requires an x401 proof bound to the paid Challenge.
 *
 * - `challenge(response)` adds one `PROOF-REQUEST` to a 402, with one request, built by
 *   `request`, for each of its Payment Challenges. The request's nonce must be the Challenge `id`.
 * - On the paid retry, before settlement, `verify` gets the `PROOF-RESPONSE` and returns the
 *   nonce the presentation is bound to. The check is valid only when it is the paid Challenge's
 *   `id`; anything else is a 401 with a `PROOF-RESULT`, and nothing settles.
 *
 * `verify` must accept a presentation once only, and must read a `credential_result_uri` only
 * from the wallet provider's host. Set the route's `expires` to the time a user needs to
 * approve: a Challenge lasts 5 minutes by default.
 *
 * @example
 * ```ts
 * const proof = X401.Server.paymentCheck({
 *   request: ({ challenge }) => signedRequest({ nonce: challenge.id }),
 *   verify: ({ proofResponse }) => verifyPresentation(proofResponse),
 * })
 * const result = await mppx.charge({ amount: '1', expires, identity: { payment: proof } })(request)
 * if (result.status === 402) return proof.challenge(result.challenge)
 * result.identity?.get(proof)
 * ```
 */
export function paymentCheck<value>(config: paymentCheck.Config<value>): PaymentCheck<value> {
  return {
    requires: [{ type: Constants.type }],
    async verify({ challenge, credential, request }) {
      const proofResponse = request.headers.get(Constants.responseHeader)
      if (!proofResponse) return { status: 'missing', reason: 'An x401 proof is required.' }
      const verified = await config.verify({ challenge, credential, proofResponse })
      if ('error' in verified) return rejected(verified.error, verified.error_description)
      if (verified.nonce !== challenge.id)
        return rejected('invalid_nonce', 'The proof is not bound to this payment Challenge')
      return { status: 'valid', value: verified.value }
    },
    async challenge(response) {
      if (response.status !== 402) return response
      const { verifier: x401 } = await import('@proof.com/x401-node')
      const headers = new Headers(response.headers)
      // One x401 payload: the specification forbids several in one header.
      headers.set(
        Constants.requestHeader,
        x401.encodePayload(
          x401.buildPayload({
            credentialRequirements: {
              digital: {
                requests: (await Promise.all(
                  Challenge.fromResponseList(response).map((challenge) =>
                    config.request({ challenge }),
                  ),
                )) as never,
              },
            },
            payment: { required: true },
          }),
        ),
      )
      return new Response(response.body, { headers, status: 402 })
    },
  }
}

/** An x401 payment check, with the function that adds its `PROOF-REQUEST` to a 402. */
export type PaymentCheck<value> = Identity.PaymentCheck<value> & {
  /** Returns a 402 with the `PROOF-REQUEST` of its Payment Challenges; other responses as is. */
  challenge: (response: Response) => Promise<Response>
}

export declare namespace paymentCheck {
  type Config<value> = {
    /** Returns the Digital Credentials API request for one Challenge, with its `id` as nonce. */
    request: (parameters: { challenge: Challenge.Challenge }) => MaybePromise<CredentialRequest>
    /**
     * Verifies the presentation of a `PROOF-RESPONSE`, once only. Returns the nonce it is bound
     * to and the value the route reads, or an x401 error code for a rejected presentation.
     */
    verify: (parameters: {
      challenge: Challenge.Challenge
      /** The payment Credential, such as to compare the payer with the credential holder. */
      credential?: Credential.Credential | undefined
      /** The encoded `PROOF-RESPONSE` header. */
      proofResponse: string
    }) => MaybePromise<
      { nonce: string; value: value } | { error: string; error_description?: string | undefined }
    >
  }
}

async function rejected(
  error: string,
  description?: string,
): Promise<Identity.Verification<never>> {
  const { verifier: x401 } = await import('@proof.com/x401-node')
  return {
    status: 'invalid',
    reason: description ?? error,
    headers: {
      [Constants.resultHeader]: x401.encodeErrorObject(
        x401.buildErrorObject({
          error,
          ...(description !== undefined && { error_description: description }),
        }),
      ),
    },
  }
}
