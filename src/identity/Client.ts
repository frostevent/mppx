import * as SigningContext from './internal/SigningContext.js'
import type * as Types from './Types.js'

/** Sends HTTP attempts with every in-scope prover applied. */
export type Client = {
  /**
   * Proves and sends one request. Redirects are followed hop by hop and each
   * hop is proved again for its own origin, so proofs never reach an origin
   * outside a prover's scope. If any prover asks to retry a rejected
   * (non-402) response, the request is proved again and resent once, except
   * for paid attempts, which are never resent.
   */
  send: (
    fetch: typeof globalThis.fetch,
    request: Request,
    context?: Types.Context,
  ) => Promise<{ request: Request; response: Response }>
  /**
   * Lets provers prepare proofs for a 402 challenge before the payment retry.
   * `url` is the request URL that produced the response; when neither it nor
   * `response.url` is known, only provers scoped to every origin run.
   */
  challenge: (response: Response, context: Types.Context, url?: string | undefined) => Promise<void>
}

const maxRedirects = 20
const redirectStatuses = new Set([301, 302, 303, 307, 308])
const bodyHeaders = [
  'content-encoding',
  'content-language',
  'content-length',
  'content-location',
  'content-type',
  'transfer-encoding',
]
const crossOriginHeaders = [
  'authorization',
  'cookie',
  'cookie2',
  'payment-authorization',
  'proxy-authorization',
]

/**
 * Creates the client runner for a list of provers.
 *
 * Provers run in list order on every attempt, sharing one attempt context.
 * List request signers last so their signatures cover headers added by
 * earlier provers.
 */
export function from(provers: readonly Types.Prover[]): Client {
  if (provers.length === 0)
    throw new TypeError('Mppx client identity must configure at least one prover.')

  async function prove(request: Request, context: Types.Context): Promise<Request> {
    const attempt: Types.ProveContext = Object.freeze({ ...context, ...SigningContext.create() })
    const origin = new URL(request.url).origin
    for (const prover of provers)
      if (inScope(prover, origin)) request = await prover.prove(request, attempt)
    return request
  }

  async function retry(response: Response, request: Request, context: Types.Context) {
    const origin = new URL(request.url).origin
    let retry = false
    for (const prover of provers)
      if (prover.retry && inScope(prover, origin) && (await prover.retry(response, context)))
        retry = true
    return retry
  }

  /** Sends a proved request, following redirects itself so each hop is re-scoped. */
  async function sendFollowing(
    fetch: typeof globalThis.fetch,
    request: Request,
    context: Types.Context,
  ): Promise<{ request: Request; response: Response }> {
    // Callers that handle redirects themselves (e.g. the paid retry) get the raw response.
    if (request.redirect !== 'follow') {
      const sent = await prove(request.clone(), context)
      return { request: sent, response: await fetch(sent) }
    }
    let current = request
    for (let hop = 0; ; hop++) {
      const sent = await prove(new Request(current.clone(), { redirect: 'manual' }), context)
      const response = await fetch(sent)
      // Runtimes that hide redirect targets (browsers) cannot be followed safely
      // with proofs attached: resend without proofs and let the runtime follow.
      if (response.type === 'opaqueredirect')
        return { request: current, response: await fetch(current.clone()) }
      const location = response.headers.get('location')
      if (!redirectStatuses.has(response.status) || !location) return { request: sent, response }
      if (hop >= maxRedirects) {
        await response.body?.cancel()
        throw new TypeError(`Identity request exceeded ${maxRedirects} redirects.`)
      }
      await response.body?.cancel()
      current = await redirect(current, response.status, new URL(location, current.url))
    }
  }

  return {
    async send(fetch, request, context = {}) {
      let result = await sendFollowing(fetch, request, context)
      // A paid attempt (context carries the challenge) is never resent: its credential may
      // already have settled, and replaying it could trigger another payment.
      if (
        !context.challenge &&
        result.response.status >= 400 &&
        result.response.status !== 402 &&
        (await retry(result.response, result.request, context))
      ) {
        await result.response.body?.cancel()
        result = await sendFollowing(fetch, request, context)
      }
      return result
    },
    async challenge(response, context, url) {
      const origin = response.url || url ? new URL(response.url || url!).origin : undefined
      for (const prover of provers)
        if (prover.retry && (origin ? inScope(prover, origin) : prover.scope === '*'))
          await prover.retry(response, context)
    },
  }
}

/**
 * Wraps a fetch implementation so every request is proved.
 *
 * Prefer `Mppx.create({ identity })`, which also passes the payment challenge to provers.
 */
export function wrapFetch(
  fetch: typeof globalThis.fetch,
  client: Client,
  context?: Types.Context,
): typeof globalThis.fetch {
  return async (input, init) =>
    (await client.send(fetch, new Request(input, init), context)).response
}

function inScope(prover: Types.Prover, origin: string): boolean {
  return prover.scope === '*' || prover.scope.includes(origin)
}

/** Builds the unproved request for the next redirect hop, following Fetch's redirect rules. */
async function redirect(request: Request, status: number, to: URL): Promise<Request> {
  const from = new URL(request.url)
  const headers = new Headers(request.headers)
  let method = request.method
  let body: ArrayBuffer | undefined =
    method === 'GET' || method === 'HEAD' ? undefined : await request.clone().arrayBuffer()
  if (
    ((status === 301 || status === 302) && method === 'POST') ||
    (status === 303 && method !== 'GET' && method !== 'HEAD')
  ) {
    method = 'GET'
    body = undefined
    for (const header of bodyHeaders) headers.delete(header)
  }
  if (from.origin !== to.origin)
    for (const [name, value] of [...headers]) {
      if (crossOriginHeaders.includes(name) || value.startsWith('Payment ')) headers.delete(name)
    }
  return new Request(to, {
    body: body ?? null,
    headers,
    method,
    redirect: 'follow',
    signal: request.signal,
  })
}
