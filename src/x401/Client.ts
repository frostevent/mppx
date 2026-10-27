import {
  agent,
  HEADER,
  type DigitalCredentialRequestEntry,
  type JsonValue,
  type X401Payload,
} from '@proof.com/x401-node'

import type * as Challenge from '../Challenge.js'
import type * as Types from './Types.js'

/**
 * Creates the x401 wallet passed as `x401` to `Mppx.create()` from `mppx/client`.
 *
 * On a `402` carrying a `PROOF-REQUEST`, mppx selects the payment challenge as usual, then
 * calls `present` with the `PROOF-REQUEST` entry whose `payment.notes` is that challenge's id,
 * before it creates the payment credential. The presentation is sent as `PROOF-RESPONSE` with
 * the payment credential on the same retry. A presentation that returns after the challenge's
 * `expires` rejects with `PaymentExpiredError` and nothing is paid.
 *
 * @example
 * ```ts
 * import { Mppx, tempo } from 'mppx/client'
 * import * as x401 from 'mppx/x401'
 *
 * const mppx = Mppx.create({
 *   methods: [tempo({ account })],
 *   x401: x401.Client.wallet({
 *     present: ({ challenge, requirement, origin }) => wallet.present(requirement, origin),
 *   }),
 * })
 * ```
 */
export function wallet(config: wallet.Config): Types.Wallet {
  return {
    headers: HEADER,
    async proofResponse({ challenge, origin, proofRequest }) {
      const payload = payloadFor(proofRequest, challenge.id)
      if (!payload) return undefined
      const requirement = agent.getDigitalCredentialRequest(payload).requests[0]!
      const presentation = await config.present({ challenge, origin, requirement })
      return agent.encodeResultArtifact(
        'data' in presentation
          ? agent.buildResultArtifact({
              credentialResult: {
                protocol: requirement.protocol,
                data: presentation.data as JsonValue,
              },
            })
          : agent.buildResultArtifactReference({
              credentialResultUri: presentation.resultUri,
              ...(presentation.expiresAt !== undefined && {
                expiresAt: presentation.expiresAt,
              }),
            }),
      )
    },
  }
}

function payloadFor(
  proofRequest: string,
  challengeId: string,
):
  | (X401Payload & {
      credential_requirements: { digital: { requests: DigitalCredentialRequestEntry[] } }
    })
  | undefined {
  for (const value of proofRequest.split(',')) {
    let payload: X401Payload
    try {
      payload = agent.decodePayload(value.trim())
    } catch {
      continue
    }
    if (payload.payment?.notes === challengeId) return payload
  }
  return undefined
}

export declare namespace wallet {
  type Config = {
    /** Obtains the presentation answering `requirement`. */
    present: (parameters: {
      /** The payment challenge mppx selected and will pay. */
      challenge: Challenge.Challenge
      /** Origin of the URL that answered the `402`. */
      origin: string
      /** The Digital Credentials API request entry bound to `challenge`. */
      requirement: Types.Requirement
    }) => Promise<Types.Presentation>
  }
}
