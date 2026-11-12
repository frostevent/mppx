import { Base64 } from 'ox'

import type * as Challenge from '../../../../Challenge.js'
import * as Expires from '../../../../Expires.js'
import type * as Identity from '../../../../identity/Types.js'
import { Constants } from '../Constants.js'
import type { CredentialRequest, CredentialResult } from '../Types.js'

/**
 * Creates a prover that answers the x401 `PROOF-REQUEST` of the Challenge it pays.
 *
 * On a 402 that requires `x401`, the prover calls `present` with the request whose nonce is the
 * selected Challenge's `id`, before the payment Credential is created, and sends the result as
 * `PROOF-RESPONSE` on the paid retry, inline (`result`) or by reference (`resultUri`). A 402
 * without a request for that Challenge throws a {@link ProofRequestError}, and a presentation
 * that returns after the Challenge expires throws: nothing is paid.
 *
 * @example
 * ```ts
 * Mppx.create({
 *   identity: [X401.Client.prover({ present, scope: ['https://api.example'] })],
 *   methods: [tempo({ account })],
 * })
 * ```
 */
export function prover(config: prover.Config): Identity.Prover {
  // Keyed by the Challenge object the client passes to both hooks, so nothing is evicted.
  const proofs = new WeakMap<Challenge.Challenge, string>()
  return {
    scope: config.scope,
    async prepare(response, { challenge, requirements }) {
      if (!requirements.some((requirement) => requirement.type === Constants.type)) return
      const { agent } = await import('@proof.com/x401-node')
      const requirement = requirementFor(
        agent,
        response.headers.get(Constants.requestHeader),
        challenge.id,
      )
      if (!requirement)
        throw new ProofRequestError('The 402 carries no x401 PROOF-REQUEST for its Challenge.')
      const presented = await config.present({ challenge, requirement })
      // The user may approve after the Challenge expired: stop before anything is paid.
      if (challenge.expires) Expires.assert(challenge.expires, challenge.id)
      proofs.set(
        challenge,
        agent.encodeResultArtifact(
          'result' in presented
            ? agent.buildResultArtifact({ credentialResult: presented.result })
            : agent.buildResultArtifactReference({
                credentialResultUri: presented.resultUri,
                ...(presented.expiresAt !== undefined && { expiresAt: presented.expiresAt }),
              }),
        ),
      )
    },
    prove(request, { challenge }) {
      const proof = challenge && proofs.get(challenge)
      if (!proof) return request
      const headers = new Headers(request.headers)
      headers.set(Constants.responseHeader, proof)
      return new Request(request, { headers })
    },
  }
}

export declare namespace prover {
  type Config = {
    /** Origins that may receive a proof. */
    readonly scope: readonly string[]
    /**
     * Presents the credential `requirement` asks for. Returns the wallet's `result`, such as from
     * `navigator.credentials.get`, or the `resultUri` where the server reads it.
     */
    readonly present: (parameters: {
      /** The Challenge the client selected and pays. */
      challenge: Challenge.Challenge
      /** The Digital Credentials API request whose nonce is the Challenge `id`. */
      requirement: CredentialRequest
    }) => Promise<
      { result: CredentialResult } | { resultUri: string; expiresAt?: string | undefined }
    >
  }
}

/** Thrown before payment when a 402 carries no usable `PROOF-REQUEST` for the selected Challenge. */
export class ProofRequestError extends Error {
  override readonly name = 'ProofRequestError'
}

/** Returns the request of a `PROOF-REQUEST` whose signed nonce is `nonce`. */
function requirementFor(
  agent: typeof import('@proof.com/x401-node').agent,
  proofRequest: string | null,
  nonce: string,
): CredentialRequest | undefined {
  if (!proofRequest) return undefined
  try {
    const { requests } = agent.getDigitalCredentialRequest(agent.decodePayload(proofRequest))
    return requests.find((entry) => {
      const [, claims] = String(entry.data.request).split('.')
      return claims !== undefined && JSON.parse(Base64.toString(claims)).nonce === nonce
    })
  } catch {
    return undefined
  }
}
