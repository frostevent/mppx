import { agent, HEADER, verifier } from '@proof.com/x401-node'
import { Challenge, Credential, Errors, Method, z } from 'mppx'
import { Mppx as ClientMppx } from 'mppx/client'
import * as X401 from 'mppx/extensions/identity/x401'
import { Mppx } from 'mppx/server'
import { Base64 } from 'ox'
import { describe, expect, test } from 'vp/test'

const secretKey = 'test-secret-key-test-secret-key-32'
const url = 'https://api.example.com/identified'

const definition = <const name extends string>(name: name) =>
  Method.from({
    name,
    intent: 'charge',
    schema: {
      credential: { payload: z.object({ token: z.string() }) },
      request: z.object({ amount: z.string() }),
    },
  })

type Present = X401.Client.prover.Config['present']

/** A signed OpenID4VP request stand-in: a JWT whose claims carry the nonce. */
const signedRequest = (nonce: string) =>
  `e30.${Base64.fromString(JSON.stringify({ nonce }), { pad: false, url: true })}.sig`
const nonceOfRequest = (request: unknown) =>
  JSON.parse(Base64.toString(String(request).split('.')[1]!)).nonce as string

/** A wallet whose results are read once, like Proof's `credential_result_uri`. */
function wallet(nonceOf: (nonce: string) => string = (nonce) => nonce) {
  const results = new Map<string, string>()
  const present: Present = async ({ requirement }) => {
    const nonce = nonceOfRequest(requirement.data.request)
    const resultUri = `https://wallet.example/results/${results.size}`
    results.set(resultUri, nonceOf(nonce))
    return { resultUri }
  }
  return { present, read: (uri: string) => results.delete(uri), results }
}

function setup(
  options: {
    composed?: boolean
    decorate?: boolean
    expires?: string
    present?: Present | false
    slowCredential?: boolean
    wallet?: ReturnType<typeof wallet>
  } = {},
) {
  const held = options.wallet ?? wallet()
  const settled: string[] = []
  const reads: string[] = []
  const serverMethod = <const name extends string>(name: name) =>
    Method.toServer(definition(name), {
      async verify({ credential }) {
        settled.push(credential.challenge.id)
        return {
          method: name,
          reference: 'ref-1',
          status: 'success',
          timestamp: '2025-01-01T00:00:00.000Z',
        } as const
      },
    })
  const proof = X401.Server.paymentCheck({
    request: ({ challenge }) => ({
      protocol: 'openid4vp-v1-signed',
      data: { request: signedRequest(challenge.id) },
    }),
    verify({ proofResponse }) {
      const artifact = verifier.decodeResultArtifact(proofResponse)
      if (artifact.credential_result)
        return { nonce: String(artifact.credential_result.data), value: { name: 'Grace' } }
      const uri = artifact.credential_result_uri!
      reads.push(uri)
      const nonce = held.results.get(uri)
      if (!held.read(uri) || nonce === undefined)
        return { error: 'invalid_result', error_description: 'The result was already read' }
      if (nonce === 'rejected') return { error: 'invalid_result' }
      return { nonce, value: { name: 'Ada' } }
    },
  })
  const chargeOptions = {
    amount: '1',
    identity: { payment: proof },
    ...(options.expires !== undefined && { expires: options.expires }),
  }
  const mppx = Mppx.create({
    realm: 'api.example.com',
    secretKey,
    methods: [serverMethod('mock'), serverMethod('other')],
  })
  const charge = options.composed
    ? mppx.compose([mppx.mock.charge, chargeOptions], [mppx.other.charge, chargeOptions])
    : mppx.mock.charge(chargeOptions)
  const requests: Request[] = []
  const responses: Response[] = []
  async function route(request: Request) {
    requests.push(request.clone())
    const result = await charge(request)
    const response =
      result.status === 402
        ? options.decorate === false
          ? result.challenge
          : await proof.challenge(result.challenge)
        : result.withReceipt(Response.json({ holder: result.identity?.get(proof) ?? null }))
    responses.push(response.clone())
    return response
  }
  const client = ClientMppx.create({
    fetch: async (input, init) => route(new Request(input, init)),
    ...(options.present !== false && {
      identity: [
        X401.Client.prover({
          present: options.present ?? held.present,
          scope: ['https://api.example.com'],
        }),
      ],
    }),
    methods: [
      Method.toClient(definition('mock'), {
        async createCredential({ challenge }) {
          if (options.slowCredential) await new Promise((resolve) => setTimeout(resolve, 20))
          return Credential.serialize({ challenge, payload: { token: 'paid' } })
        },
      }),
    ],
    polyfill: false,
  })
  return { client, reads, requests, responses, route, settled }
}

describe('x401 bound to the payment Challenge', () => {
  test('one 402 and one paid retry: the proof is read once and the payment settles once', async () => {
    const { client, reads, responses, settled } = setup()
    const response = await client.fetch(url)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ holder: { name: 'Ada' } })
    expect(responses.map((r) => r.status)).toEqual([402, 200])
    expect(responses[0]!.headers.get('Identity-Required')).toBe('x401')
    const payload = agent.decodePayload(responses[0]!.headers.get(HEADER.PROOF_REQUEST)!)
    expect(payload.payment).toEqual({ required: true })
    expect(
      payload.credential_requirements.digital.requests.map((entry) =>
        nonceOfRequest(entry.data.request),
      ),
    ).toEqual(settled)
    expect(reads).toHaveLength(1)
    expect(settled).toHaveLength(1)
  })

  test('an inline result from a local wallet is sent in the PROOF-RESPONSE', async () => {
    const { client, requests, settled } = setup({
      present: async ({ requirement }) => ({
        result: {
          protocol: requirement.protocol,
          data: nonceOfRequest(requirement.data.request),
        },
      }),
    })
    const response = await client.fetch(url)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ holder: { name: 'Grace' } })
    const artifact = verifier.decodeResultArtifact(
      requests.at(-1)!.headers.get(HEADER.PROOF_RESPONSE)!,
    )
    expect(artifact.credential_result?.data).toBe(settled[0])
    expect(settled).toHaveLength(1)
  })

  test('composed offers: one PROOF-REQUEST with a request for each Challenge', async () => {
    const { client, route, settled } = setup({ composed: true })
    const offered = await route(new Request(url))
    // One x401 object in the header, as the x401 specification requires.
    const payload = agent.detectProofRequirement({ headers: offered.headers })!.payload
    const nonces = payload.credential_requirements.digital.requests.map((entry) =>
      nonceOfRequest(entry.data.request),
    )
    expect(nonces).toEqual(Challenge.fromResponseList(offered).map((challenge) => challenge.id))
    expect(nonces).toHaveLength(2)
    const response = await client.fetch(url)
    expect(response.status).toBe(200)
    expect(settled).toHaveLength(1)
  })

  test('concurrent payments on one client each carry their own proof', async () => {
    const { client, settled } = setup({ slowCredential: true })
    const responses = await Promise.all(Array.from({ length: 20 }, () => client.fetch(url)))
    expect(responses.map((response) => response.status)).toEqual(Array(20).fill(200))
    expect(new Set(settled).size).toBe(20)
  })

  test('a captured PROOF-RESPONSE cannot be used again', async () => {
    const { client, requests, route, settled } = setup()
    expect((await client.fetch(url)).status).toBe(200)
    const replayed = await route(requests.at(-1)!)
    expect(replayed.status).toBe(401)
    expect(settled).toHaveLength(1)
  })

  test('a proof bound to another nonce is rejected and nothing settles', async () => {
    const { client, responses, settled } = setup({ wallet: wallet(() => 'another-challenge') })
    const response = await client.fetch(url)
    expect(response.status).toBe(401)
    expect(agent.decodeErrorObject(response.headers.get(HEADER.PROOF_RESULT)!).error).toBe(
      'invalid_nonce',
    )
    expect(responses.map((r) => r.status)).toEqual([402, 401])
    expect(settled).toEqual([])
  })

  test('a rejected presentation answers 401 with its PROOF-RESULT and nothing settles', async () => {
    const { client, settled } = setup({ wallet: wallet(() => 'rejected') })
    const response = await client.fetch(url)
    expect(response.status).toBe(401)
    expect(agent.decodeErrorObject(response.headers.get(HEADER.PROOF_RESULT)!).error).toBe(
      'invalid_result',
    )
    expect(settled).toEqual([])
  })

  test('a client without the prover is rejected and nothing settles', async () => {
    const { client, responses, settled } = setup({ present: false })
    const response = await client.fetch(url)
    expect(response.status).toBe(401)
    expect(responses.map((r) => r.status)).toEqual([402, 401])
    expect(settled).toEqual([])
  })

  test('a 402 without its PROOF-REQUEST stops the client before it pays', async () => {
    const { client, responses, settled } = setup({ decorate: false })
    await expect(client.fetch(url)).rejects.toBeInstanceOf(X401.Client.ProofRequestError)
    expect(responses.map((r) => r.status)).toEqual([402])
    expect(settled).toEqual([])
  })

  test('a presentation approved after the Challenge expired stops before it pays', async () => {
    const held = wallet()
    const { client, responses, settled } = setup({
      expires: new Date(Date.now() + 200).toISOString(),
      present: async (parameters) => {
        await new Promise((resolve) => setTimeout(resolve, 400))
        return held.present(parameters)
      },
      wallet: held,
    })
    await expect(client.fetch(url)).rejects.toBeInstanceOf(Errors.PaymentExpiredError)
    expect(responses.map((r) => r.status)).toEqual([402])
    expect(settled).toEqual([])
  })
})
