import * as Identity from 'mppx/identity'
import { expect, test, vi } from 'vp/test'

const header =
  (name: string, value: string): Identity.Prover['prove'] =>
  (request) => {
    const headers = new Headers(request.headers)
    headers.set(name, value)
    return new Request(request, { headers })
  }

test('runs in-scope provers in order with one frozen attempt context', async () => {
  const contexts: Identity.ProveContext[] = []
  const order: string[] = []
  const prover = (name: string, scope: Identity.Prover['scope']): Identity.Prover => ({
    scope,
    prove(request, context) {
      contexts.push(context)
      order.push(name)
      return header(`X-${name}`, context.nonce)(request, context)
    },
  })
  const client = Identity.Client.from([
    prover('first', '*'),
    prover('skipped', ['https://elsewhere.example']),
    prover('last', ['https://merchant.example']),
  ])
  const fetch = vi.fn(async () => new Response('ok'))
  const { request } = await client.send(fetch as never, new Request('https://merchant.example/a'))

  expect(order).toEqual(['first', 'last'])
  expect(contexts[0]).toBe(contexts[1])
  expect(Object.isFrozen(contexts[0])).toBe(true)
  expect(contexts[0]!.nonce).toMatch(/^[A-Za-z0-9_-]{86}$/)
  expect(request.headers.get('X-first')).toBe(contexts[0]!.nonce)
  expect(request.headers.has('X-skipped')).toBe(false)
})

test('resends a rejected request once when a prover asks, with a new context', async () => {
  const nonces: string[] = []
  const retry = vi.fn(() => true)
  const client = Identity.Client.from([
    {
      scope: '*',
      prove(request, context) {
        nonces.push(context.nonce)
        return request
      },
      retry,
    },
  ])
  const fetch = vi.fn(async () => new Response(null, { status: 403 }))
  const { response } = await client.send(
    fetch as never,
    new Request('https://merchant.example', { body: 'x', method: 'POST' }),
  )

  expect(response.status).toBe(403)
  expect(fetch).toHaveBeenCalledTimes(2)
  expect(retry).toHaveBeenCalledTimes(1)
  expect(new Set(nonces).size).toBe(2)
})

test('does not resend a 402 and passes the payment challenge to provers', async () => {
  const challenge = { id: 'challenge-id' } as never
  const seen: Identity.Context[] = []
  const client = Identity.Client.from([
    {
      scope: '*',
      prove(request, context) {
        seen.push(context)
        return request
      },
      retry(_, context) {
        seen.push(context)
        return true
      },
    },
  ])
  const fetch = vi.fn(async () => new Response(null, { status: 402 }))
  const { response } = await client.send(fetch as never, new Request('https://merchant.example'), {
    challenge,
  })
  await client.challenge(response, { challenge })

  expect(fetch).toHaveBeenCalledTimes(1)
  expect(seen.map((context) => context.challenge)).toEqual([challenge, challenge])
})

test('rejects an empty prover list', () => {
  expect(() => Identity.Client.from([])).toThrow(
    'Mppx client identity must configure at least one prover.',
  )
})
