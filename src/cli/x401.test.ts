import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { pathToFileURL } from 'node:url'

import { HEADER, verifier } from '@proof.com/x401-node'
import { afterAll, describe, expect, test } from 'vp/test'
import * as Http from '~test/Http.js'

import * as Challenge from '../Challenge.js'
import * as Constants from '../Constants.js'
import * as Credential from '../Credential.js'
import * as x401 from '../x401/index.js'
import cli from './cli.js'

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mppx-cli-x401-'))
const configPath = path.join(directory, 'mppx.config.mjs')
const commandPath = path.join(directory, 'present.mjs')
const stdinPath = path.join(directory, 'stdin.txt')
const proof = 'proof-response-for-the-selected-challenge'
const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(commandPath)}`

fs.writeFileSync(
  configPath,
  `
  import { Credential, Method, z } from '${pathToFileURL(path.join(process.cwd(), 'src/index.ts')).href}'
  export default { methods: [Method.toClient(Method.from({
    name: 'mock', intent: 'charge',
    schema: { credential: { payload: z.object({}) },
      request: z.object({ amount: z.string(), currency: z.string() }),
    }
  }), { async createCredential({ challenge }) {
    return Credential.serialize({ challenge, payload: {} })
  } })] }
`,
)
fs.writeFileSync(
  commandPath,
  `
  import { readFileSync, writeFileSync } from 'node:fs'
  writeFileSync(${JSON.stringify(stdinPath)}, readFileSync(0, 'utf8'))
  process.stderr.write('Approve the presentation\\n')
  await new Promise((resolve) => setTimeout(resolve, Number(process.env.X401_TEST_DELAY_MS ?? 0)))
  process.stdout.write(process.env.X401_TEST_PROOF ?? '')
  process.exit(Number(process.env.X401_TEST_EXIT ?? 0))
`,
)

afterAll(() => {
  fs.rmSync(directory, { recursive: true, force: true })
})

const proofVerifier = x401.Server.verifier({
  request: ({ challenge }) => ({
    protocol: 'openid4vp-v1-unsigned',
    data: { nonce: challenge.id },
  }),
  verify: () => ({ error: 'unused' }),
})

function challengeOf(id: string, method: string, expires?: string) {
  return Challenge.from({
    id,
    intent: 'charge',
    method,
    realm: 'localhost',
    request: { amount: '1', currency: 'MOCK' },
    ...(expires && { expires }),
  })
}

async function createServer(
  options: {
    expires?: string
    onPaid?: (
      req: { headers: Record<string, string | string[] | undefined> },
      res: { writeHead: (status: number, headers?: Record<string, string>) => void },
    ) => void
  } = {},
) {
  const unsupported = challengeOf('unsupported', 'other')
  const selected = challengeOf('selected', 'mock', options.expires)
  const entries = await Promise.all(
    [unsupported, selected].map((challenge) =>
      proofVerifier.proofRequest({ challenge, scope: 'urn:example:scope' }),
    ),
  )
  const paid: { authorization?: string | undefined; proofResponse?: string | undefined }[] = []
  const server = await Http.createServer((req, res) => {
    const authorization = req.headers.authorization
    if (authorization) {
      paid.push({
        authorization,
        proofResponse: req.headers[HEADER.PROOF_RESPONSE.toLowerCase()] as string | undefined,
      })
      options.onPaid?.(req, res)
      res.end('paid')
      return
    }
    res.writeHead(402, {
      [Constants.Headers.wwwAuthenticate]: [unsupported, selected]
        .map(Challenge.serialize)
        .join(', '),
      [HEADER.PROOF_REQUEST]: entries.join(', '),
    })
    res.end()
  })
  return { entries, paid, server }
}

async function serve(argv: string[], env: Record<string, string | undefined> = {}) {
  let output = ''
  let stderr = ''
  let exitCode: number | undefined
  const saved: Record<string, string | undefined> = {}
  const environment = {
    X401_TEST_DELAY_MS: undefined,
    X401_TEST_EXIT: undefined,
    X401_TEST_PROOF: proof,
    XDG_CONFIG_HOME: path.join(directory, 'config'),
    XDG_DATA_HOME: path.join(directory, 'data'),
    XDG_STATE_HOME: path.join(directory, 'state'),
    ...env,
  }
  for (const [key, value] of Object.entries(environment)) {
    saved[key] = process.env[key]
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
  const stdoutWrite = process.stdout.write
  const stderrWrite = process.stderr.write
  process.stdout.write = ((chunk: unknown) => {
    output += String(chunk)
    return true
  }) as typeof process.stdout.write
  process.stderr.write = ((chunk: unknown) => {
    stderr += String(chunk)
    return true
  }) as typeof process.stderr.write
  try {
    await cli.serve([...argv, '--config', configPath], {
      stdout(s: string) {
        output += s
      },
      exit(code: number) {
        exitCode = code
      },
    })
  } finally {
    process.stdout.write = stdoutWrite
    process.stderr.write = stderrWrite
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
  return { exitCode, output, stderr }
}

describe('x401', () => {
  test('presents the PROOF-REQUEST entry of the selected challenge and sends its PROOF-RESPONSE', async () => {
    const { entries, paid, server } = await createServer()
    try {
      const { exitCode, output } = await serve([server.url, '-s', '--x401-command', command])
      expect(exitCode).toBeUndefined()
      expect(output).toContain('paid')
      expect(fs.readFileSync(stdinPath, 'utf8')).toBe(`${entries[1]}\n`)
      expect(paid).toHaveLength(1)
      expect(Credential.deserialize(paid[0]!.authorization!).challenge.id).toBe('selected')
      expect(paid[0]!.proofResponse).toBe(proof)
    } finally {
      server.close()
    }
  })

  test('redacts the PROOF-RESPONSE from the printed request headers', async () => {
    const { paid, server } = await createServer()
    try {
      const { exitCode, output, stderr } = await serve([
        server.url,
        '-vv',
        '--x401-command',
        command,
      ])
      expect(exitCode).toBeUndefined()
      expect(paid[0]!.proofResponse).toBe(proof)
      expect(stderr).toContain(`> ${HEADER.PROOF_RESPONSE}: [redacted]`)
      expect(`${output}${stderr}`).not.toContain(proof)
    } finally {
      server.close()
    }
  })

  test('requires --x401-command when the selected challenge has a PROOF-REQUEST entry', async () => {
    const { paid, server } = await createServer()
    try {
      const { exitCode, output } = await serve([server.url, '-s'])
      expect(exitCode).toBe(2)
      expect(output).toContain('X401_COMMAND_REQUIRED')
      expect(output).toContain('--x401-command')
      expect(paid).toHaveLength(0)
    } finally {
      server.close()
    }
  })

  test.each([
    { env: { X401_TEST_EXIT: '3' }, message: 'exited with status 3' },
    { env: { X401_TEST_PROOF: '' }, message: 'did not print a PROOF-RESPONSE' },
    { env: { X401_TEST_PROOF: 'two lines\nof output' }, message: 'did not print a PROOF-RESPONSE' },
  ])('fails without paying when the command $message', async ({ env, message }) => {
    const { paid, server } = await createServer()
    try {
      const { exitCode, output } = await serve([server.url, '-s', '--x401-command', command], env)
      expect(exitCode).toBe(1)
      expect(output).toContain('X401_COMMAND_FAILED')
      expect(output).toContain(message)
      expect(paid).toHaveLength(0)
    } finally {
      server.close()
    }
  })

  test('fails without paying when the challenge expires while the command runs', async () => {
    const { paid, server } = await createServer({
      expires: new Date(Date.now() + 1_000).toISOString(),
    })
    try {
      const { exitCode, output } = await serve([server.url, '-s', '--x401-command', command], {
        X401_TEST_DELAY_MS: '1500',
      })
      expect(exitCode).toBe(1)
      expect(output).toContain('PAYMENT_EXPIRED')
      expect(output).not.toContain(proof)
      expect(paid).toHaveLength(0)
    } finally {
      server.close()
    }
  })

  test('reports a 401 with PROOF-RESULT as a rejected proof', async () => {
    const { paid, server } = await createServer({
      onPaid(_req, res) {
        res.writeHead(401, {
          [HEADER.PROOF_RESULT]: verifier.encodeErrorObject(
            verifier.buildErrorObject({
              error: 'invalid_result',
              error_description: 'The presentation is not bound to this payment challenge',
            }),
          ),
        })
      },
    })
    try {
      const { exitCode, output } = await serve([server.url, '-s', '--x401-command', command])
      expect(paid).toHaveLength(1)
      expect(exitCode).toBe(75)
      expect(output).toContain('PROOF_REJECTED')
      expect(output).toContain(
        'invalid_result: The presentation is not bound to this payment challenge',
      )
      expect(output).not.toContain(proof)
    } finally {
      server.close()
    }
  })
})
