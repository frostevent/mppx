import { agent, HEADER } from '@proof.com/x401-node'
import { Challenge, Credential, Errors, Method, z } from 'mppx'
import { Mppx as ClientMppx } from 'mppx/client'
import { Mppx } from 'mppx/server'
import * as x401 from 'mppx/x401'
import { afterEach, describe, expect, test, vi } from 'vp/test'

const realm = 'api.example.com'
const secretKey = 'test-secret-key-test-secret-key-32'
const url = 'https://api.example.com/identified'
const scope = 'urn:example:scope:basic'

const definition = <const name extends string>(name: name) =>
  Method.from({
    name,
    intent: 'charge',
    schema: {
      credential: { payload: z.object({ token: z.string() }) },
      request: z.object({ amount: z.string() }),
    },
  })

afterEach(() => {
  vi.unstubAllGlobals()
})

function setup(options: { composed?: boolean; expires?: string; x401?: boolean } = {}) {
  const settled: string[] = []
  const requested: { challengeId: string; scope: string }[] = []
  const verified: { challengeId: string; data: unknown }[] = []
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
  const config = {
    realm,
    secretKey,
    x401: x401.Server.verifier({
      request({ challenge, scope }) {
        requested.push({ challengeId: challenge.id, scope })
        return { protocol: 'openid4vp-v1-signed', data: { request: `jar:${challenge.id}` } }
      },
      verify({ challenge, data }) {
        verified.push({ challengeId: challenge.id, data })
        const { vp_token } = data as { vp_token: string | string[] }
        if (vp_token === 'rejected')
          return { error: 'invalid_result', error_description: 'The presentation was rejected' }
        if (vp_token === 'unavailable') throw new Error('The verification service is unavailable.')
        return {
          challengeIds: (Array.isArray(vp_token) ? vp_token : [vp_token]).map((token) =>
            token.startsWith('jar:') ? token.slice('jar:'.length) : undefined,
          ),
          value: { name: 'Ada' },
        }
      },
    }),
  }
  const chargeOptions = {
    amount: '1',
    ...(options.expires !== undefined && { expires: options.expires }),
    ...(options.x401 !== false && { x401: { scope } }),
  }
  const charge = options.composed
    ? Mppx.create({ ...config, methods: [serverMethod('mock'), serverMethod('other')] }).charge(
        chargeOptions,
      )
    : Mppx.create({ ...config, methods: [serverMethod('mock')] }).charge(chargeOptions)
  const requests: Request[] = []
  async function route(request: Request) {
    requests.push(request.clone())
    const result = await charge(request)
    if (result.status === 402) return result.challenge
    return result.withReceipt(Response.json({ x401: result.x401 ?? null }))
  }
  return { requested, requests, route, settled, verified }
}

function client(
  route: (request: Request) => Promise<Response>,
  present: x401.Client.wallet.Config['present'],
) {
  return ClientMppx.create({
    fetch: async (input, init) => route(new Request(input, init)),
    methods: [
      Method.toClient(definition('mock'), {
        async createCredential({ challenge }) {
          return Credential.serialize({ challenge, payload: { token: 'paid' } })
        },
      }),
    ],
    polyfill: false,
    x401: x401.Client.wallet({ present }),
  })
}

const presentRequest: x401.Client.wallet.Config['present'] = async ({ requirement }) => ({
  data: { vp_token: (requirement.data as { request: string }).request },
})

function proofRequests(response: Response) {
  return response.headers
    .get(HEADER.PROOF_REQUEST)!
    .split(',')
    .map((value) => agent.decodePayload(value.trim()))
}

const proofResponse = (vpToken: string | string[]) =>
  agent.encodeResultArtifact(
    agent.buildResultArtifact({
      credentialResult: { protocol: 'openid4vp-v1-signed', data: { vp_token: vpToken } },
    }),
  )

const paidRequest = (challenge: Challenge.Challenge, proof?: string) =>
  new Request(url, {
    headers: {
      Authorization: Credential.serialize({ challenge, payload: { token: 'paid' } }),
      ...(proof !== undefined && { [HEADER.PROOF_RESPONSE]: proof }),
    },
  })

describe('x401 server', () => {
  test('a 402 carries one PROOF-REQUEST entry bound to its payment challenge', async () => {
    const { requested, route } = setup()

    const response = await route(new Request(url))

    expect(response.status).toBe(402)
    const [challenge] = Challenge.fromResponseList(response)
    expect(requested).toEqual([{ challengeId: challenge!.id, scope }])
    const [payload, ...rest] = proofRequests(response)
    expect(rest).toEqual([])
    expect(payload!.payment).toEqual({
      required: true,
      scheme_hint: 'mpp/draft-httpauth-payment-00',
      notes: challenge!.id,
    })
    expect(payload!.credential_requirements.digital.requests).toEqual([
      { protocol: 'openid4vp-v1-signed', data: { request: `jar:${challenge!.id}` } },
    ])
  })

  test('a composed 402 carries one PROOF-REQUEST entry per payment challenge', async () => {
    const { route } = setup({ composed: true })

    const response = await route(new Request(url))

    const challenges = Challenge.fromResponseList(response)
    expect(challenges).toHaveLength(2)
    expect(proofRequests(response).map((payload) => payload.payment?.notes)).toEqual(
      challenges.map((challenge) => challenge.id),
    )
  })

  test('a route without x401 is plain MPP on a server configured with a verifier', async () => {
    const { requested, route, settled } = setup({ x401: false })
    const response = await route(new Request(url))
    const [challenge] = Challenge.fromResponseList(response)

    const paid = await route(paidRequest(challenge!))

    expect(response.headers.has(HEADER.PROOF_REQUEST)).toBe(false)
    expect(requested).toEqual([])
    expect(paid.status).toBe(200)
    expect(settled).toEqual([challenge!.id])
  })

  test('a paid request without PROOF-RESPONSE gets 401 + PROOF-REQUEST for its challenge and is not settled', async () => {
    const { route, settled } = setup()
    const [challenge] = Challenge.fromResponseList(await route(new Request(url)))

    const response = await route(paidRequest(challenge!))

    expect(response.status).toBe(401)
    expect(response.headers.has('WWW-Authenticate')).toBe(false)
    expect(proofRequests(response).map((payload) => payload.payment?.notes)).toEqual([
      challenge!.id,
    ])
    expect(settled).toEqual([])
  })

  test('a rejected presentation gets 401 + PROOF-RESULT and is not settled', async () => {
    const { route, settled } = setup()
    const [challenge] = Challenge.fromResponseList(await route(new Request(url)))

    const response = await route(paidRequest(challenge!, proofResponse('rejected')))

    expect(response.status).toBe(401)
    expect(response.headers.has('WWW-Authenticate')).toBe(false)
    expect(agent.decodeErrorObject(response.headers.get(HEADER.PROOF_RESULT)!)).toMatchObject({
      error: 'invalid_result',
      error_description: 'The presentation was rejected',
    })
    expect(settled).toEqual([])
  })

  test('a presentation bound to another challenge gets 401 + PROOF-RESULT and is not settled', async () => {
    const { route, settled } = setup()
    const [challenge] = Challenge.fromResponseList(await route(new Request(url)))
    const [other] = Challenge.fromResponseList(await route(new Request(url)))

    const response = await route(paidRequest(challenge!, proofResponse(`jar:${other!.id}`)))

    expect(response.status).toBe(401)
    expect(agent.decodeErrorObject(response.headers.get(HEADER.PROOF_RESULT)!).error).toBe(
      'invalid_result',
    )
    expect(settled).toEqual([])
  })

  test.each([
    { name: 'a credential without a binding', bound: (id: string) => [`jar:${id}`, 'unbound'] },
    { name: 'no credential', bound: () => [] },
  ])('a presentation with $name gets 401 + PROOF-RESULT and is not settled', async ({ bound }) => {
    const { route, settled } = setup()
    const [challenge] = Challenge.fromResponseList(await route(new Request(url)))

    const response = await route(paidRequest(challenge!, proofResponse(bound(challenge!.id))))

    expect(response.status).toBe(401)
    expect(agent.decodeErrorObject(response.headers.get(HEADER.PROOF_RESULT)!).error).toBe(
      'invalid_result',
    )
    expect(settled).toEqual([])
  })

  test('a verifier that throws propagates the error and nothing is settled', async () => {
    const { route, settled } = setup()
    const [challenge] = Challenge.fromResponseList(await route(new Request(url)))

    await expect(route(paidRequest(challenge!, proofResponse('unavailable')))).rejects.toThrow(
      'The verification service is unavailable.',
    )
    expect(settled).toEqual([])
  })

  test('a malformed PROOF-RESPONSE gets 400 + PROOF-RESULT and is not settled', async () => {
    const { route, settled, verified } = setup()
    const [challenge] = Challenge.fromResponseList(await route(new Request(url)))

    const response = await route(paidRequest(challenge!, 'not-a-result-artifact'))

    expect(response.status).toBe(400)
    expect(agent.decodeErrorObject(response.headers.get(HEADER.PROOF_RESULT)!).error).toBe(
      'invalid_response',
    )
    expect(verified).toEqual([])
    expect(settled).toEqual([])
  })

  test('a route with x401 on a server without a verifier is refused', () => {
    const mppx = Mppx.create({
      methods: [Method.toServer(definition('mock'), { verify: async () => ({}) as never })],
      realm,
      secretKey,
    })

    expect(() => mppx.charge({ amount: '1', x401: { scope } })).toThrow(/no x401 verifier/)
  })
})

describe('x401 client', () => {
  test('presents for the selected challenge and sends PROOF-RESPONSE with the payment on one retry', async () => {
    const { requests, route, settled } = setup()
    const presented: Parameters<x401.Client.wallet.Config['present']>[0][] = []

    const response = await client(route, async (parameters) => {
      presented.push(parameters)
      return presentRequest(parameters)
    }).fetch(url)

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ x401: { name: 'Ada' } })
    expect(response.headers.get('Payment-Receipt')).toBeTruthy()
    expect(presented).toHaveLength(1)
    expect(presented[0]!.origin).toBe('https://api.example.com')
    expect(presented[0]!.requirement).toEqual({
      protocol: 'openid4vp-v1-signed',
      data: { request: `jar:${presented[0]!.challenge.id}` },
    })
    expect(requests).toHaveLength(2)
    expect(settled).toEqual([presented[0]!.challenge.id])
  })

  test('on a composed 402 the presentation answers the entry of the challenge mppx pays', async () => {
    const { route, settled } = setup({ composed: true })
    const presented: Challenge.Challenge[] = []

    const response = await client(route, async (parameters) => {
      presented.push(parameters.challenge)
      return presentRequest(parameters)
    }).fetch(url)

    expect(response.status).toBe(200)
    expect(presented.map((challenge) => challenge.method)).toEqual(['mock'])
    expect(settled).toEqual([presented[0]!.id])
  })

  test('a presentation by reference is fetched by the server', async () => {
    const { route, verified } = setup()
    const fetched: string[] = []
    let pending = ''
    vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
      fetched.push(String(input))
      return Response.json({
        protocol: 'openid4vp-v1-signed',
        data: { vp_token: `jar:${pending}` },
      })
    })

    const response = await client(route, async ({ challenge }) => {
      pending = challenge.id
      return { resultUri: 'https://wallet.example/results/1' }
    }).fetch(url)

    expect(response.status).toBe(200)
    expect(fetched).toEqual(['https://wallet.example/results/1'])
    expect(verified).toEqual([{ challengeId: pending, data: { vp_token: `jar:${pending}` } }])
  })

  test('a rejected presentation returns the 401 without paying again', async () => {
    const { requests, route, settled } = setup()

    const response = await client(route, async () => ({ data: { vp_token: 'rejected' } })).fetch(
      url,
    )

    expect(response.status).toBe(401)
    expect(response.headers.has(HEADER.PROOF_RESULT)).toBe(true)
    expect(requests).toHaveLength(2)
    expect(settled).toEqual([])
  })

  test('a presentation returned after the payment challenge expired is discarded before paying', async () => {
    const { requests, route } = setup({ expires: new Date(Date.now() + 100).toISOString() })

    await expect(
      client(route, async (parameters) => {
        await new Promise((resolve) => setTimeout(resolve, 200))
        return presentRequest(parameters)
      }).fetch(url),
    ).rejects.toBeInstanceOf(Errors.PaymentExpiredError)
    expect(requests).toHaveLength(1)
  })

  test('a 402 without PROOF-REQUEST is paid without presenting', async () => {
    const { route, settled } = setup({ x401: false })
    let presented = false

    const response = await client(route, async (parameters) => {
      presented = true
      return presentRequest(parameters)
    }).fetch(url)

    expect(response.status).toBe(200)
    expect(presented).toBe(false)
    expect(settled).toHaveLength(1)
  })
})
