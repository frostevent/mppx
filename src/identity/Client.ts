import * as SigningContext from './internal/SigningContext.js'
import type * as Types from './Types.js'

/** Sends HTTP attempts with every in-scope prover applied. */
export type Client = {
  /**
   * Proves and sends one request. If any prover asks to retry a rejected
   * (non-402) response, the request is proved again and resent once.
   */
  send: (
    fetch: typeof globalThis.fetch,
    request: Request,
    context?: Types.Context,
  ) => Promise<{ request: Request; response: Response }>
  /** Lets provers prepare proofs for a 402 challenge before the payment retry. */
  challenge: (response: Response, context: Types.Context) => Promise<void>
}

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

  return {
    async send(fetch, request, context = {}) {
      let sent = await prove(request.clone(), context)
      let response = await fetch(sent)
      if (
        response.status >= 400 &&
        response.status !== 402 &&
        (await retry(response, sent, context))
      ) {
        await response.body?.cancel()
        sent = await prove(request.clone(), context)
        response = await fetch(sent)
      }
      return { request: sent, response }
    },
    async challenge(response, context) {
      const url = response.url || undefined
      for (const prover of provers)
        if (prover.retry && (!url || inScope(prover, new URL(url).origin)))
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
