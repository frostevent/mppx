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

test('re-proves each redirect hop for its own origin', async () => {
  const seen: { url: string; proof: string | null; method: string; auth: string | null }[] = []
  const client = Identity.Client.from([
    { scope: ['https://a.example'], prove: header('X-Proof', 'a') },
  ])
  const fetch = vi.fn(async (request: Request) => {
    seen.push({
      auth: request.headers.get('authorization'),
      method: request.method,
      proof: request.headers.get('X-Proof'),
      url: request.url,
    })
    expect(request.redirect).toBe('manual')
    if (request.url === 'https://a.example/start')
      return new Response(null, { headers: { location: '/next' }, status: 302 })
    if (request.url === 'https://a.example/next')
      return new Response(null, { headers: { location: 'https://b.example/end' }, status: 303 })
    return new Response('ok')
  })
  const { response } = await client.send(
    fetch as never,
    new Request('https://a.example/start', {
      body: 'x',
      headers: { authorization: 'Bearer t' },
      method: 'POST',
    }),
  )
  expect(await response.text()).toBe('ok')
  expect(seen).toEqual([
    { auth: 'Bearer t', method: 'POST', proof: 'a', url: 'https://a.example/start' },
    { auth: 'Bearer t', method: 'GET', proof: 'a', url: 'https://a.example/next' },
    { auth: null, method: 'GET', proof: null, url: 'https://b.example/end' },
  ])
})

test('only runs unscoped provers for a challenge from an unknown origin', async () => {
  const ran: string[] = []
  const prover = (name: string, scope: Identity.Prover['scope']): Identity.Prover => ({
    scope,
    prove: (request) => request,
    retry() {
      ran.push(name)
      return false
    },
  })
  const client = Identity.Client.from([prover('any', '*'), prover('scoped', ['https://a.example'])])
  await client.challenge(new Response(null, { status: 402 }), {})
  expect(ran).toEqual(['any'])
  await client.challenge(new Response(null, { status: 402 }), {}, 'https://a.example/x')
  expect(ran).toEqual(['any', 'any', 'scoped'])
})

test('never resends a paid attempt', async () => {
  const retry = vi.fn(() => true)
  const client = Identity.Client.from([{ scope: '*', prove: (request) => request, retry }])
  const fetch = vi.fn(async () => new Response(null, { status: 403 }))
  await client.send(fetch as never, new Request('https://merchant.example'), {
    challenge: { id: 'paid' } as never,
  })
  expect(fetch).toHaveBeenCalledTimes(1)
  expect(retry).not.toHaveBeenCalled()
})

test('never replays a request after an opaque redirect', async () => {
  const client = Identity.Client.from([{ scope: '*', prove: (request) => request }])
  const fetch = vi.fn(async () => Response.redirect('https://merchant.example/next', 302))
  const opaque = { ...new Response(null), type: 'opaqueredirect' } as unknown as Response
  fetch.mockResolvedValueOnce(opaque)
  await expect(
    client.send(
      fetch as never,
      new Request('https://merchant.example', { body: 'x', method: 'POST' }),
    ),
  ).rejects.toThrow('Identity requests require a runtime that exposes manual redirect responses.')
  expect(fetch).toHaveBeenCalledTimes(1)
})

test('sends integrity-checked requests once without following redirects', async () => {
  const client = Identity.Client.from([{ scope: '*', prove: header('X-Proof', 'p') }])
  const seen: Request[] = []
  const fetch = vi.fn(async (request: Request) => {
    seen.push(request)
    return new Response('ok')
  })
  await client.send(
    fetch as never,
    new Request('https://merchant.example/a.js', { integrity: 'sha256-abc' }),
  )
  expect(seen).toHaveLength(1)
  expect(seen[0]!.redirect).toBe('error')
  expect(seen[0]!.integrity).toBe('sha256-abc')
  expect(seen[0]!.headers.get('X-Proof')).toBe('p')
})

test('preserves request policies and refuses cross-origin hops in same-origin mode', async () => {
  const client = Identity.Client.from([{ scope: '*', prove: (request) => request }])
  const seen: Request[] = []
  const fetch = vi.fn(async (request: Request) => {
    seen.push(request)
    if (request.url.endsWith('/start'))
      return new Response(null, { headers: { location: '/next' }, status: 307 })
    if (request.url.endsWith('/next'))
      return new Response(null, { headers: { location: 'https://other.example/x' }, status: 307 })
    return new Response('ok')
  })
  await expect(
    client.send(
      fetch as never,
      new Request('https://merchant.example/start', {
        body: 'secret',
        credentials: 'omit',
        method: 'POST',
        mode: 'same-origin',
      }),
    ),
  ).rejects.toThrow("mode 'same-origin' refused a redirect to https://other.example")
  expect(seen.map((request) => request.url)).toEqual([
    'https://merchant.example/start',
    'https://merchant.example/next',
  ])
  expect(seen[1]!.credentials).toBe('omit')
})
