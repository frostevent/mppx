type Json = string | number | boolean | null | Json[] | { [key: string]: Json }

/**
 * One Digital Credentials API request of a `PROOF-REQUEST`: a `DigitalCredentialRequestEntry` of
 * `@proof.com/x401-node`, declared here so the types load without that optional package.
 */
export type CredentialRequest = {
  /** Digital Credentials API protocol of `data`. */
  protocol: 'openid4vp-v1-signed' | 'openid4vp-v1-unsigned'
  /** The protocol's request, such as `{ request }` with the signed request. */
  data: { [key: string]: Json }
}

/**
 * A credential result sent inline in a `PROOF-RESPONSE`: a `CredentialResult` of
 * `@proof.com/x401-node`, declared here so the types load without that optional package.
 */
export type CredentialResult = {
  /** Digital Credentials API protocol of `data`. */
  protocol: string
  /** The result the wallet returned, such as `{ vp_token }`. */
  data: Json
}
