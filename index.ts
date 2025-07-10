import * as client from 'openid-client';
import { webcrypto } from 'crypto';
import { readFileSync } from 'fs';
import {CustomFetchOptions} from "openid-client";
const { subtle } = webcrypto;

let server!: URL
let key!: client.CryptoKey | client.PrivateKey
let clientId!: string
let clientMetadata!: Partial<client.ClientMetadata> | string | undefined

(async () => {
    server = new URL('https://sts-cert.bportugal.net/adfs/.well-known/openid-configuration');
    clientId = 'https://bpnetsvc-faitdexxx-cert.bportugal.pt/'

    let envHttpProxyAgent = new undici.EnvHttpProxyAgent()

    key= {key:}

// @ts-ignore
    config[client.customFetch] = (...args) => {
        // @ts-ignore
        return undici.fetch(args[0], { ...args[1], dispatcher: envHttpProxyAgent }) // prettier-ignore
    }
    const privateKey = await importPrivateKey('./private_key.pem');
    key= {key:privateKey,kid:clientId}
// @ts-ignore
    let config = await client.discovery(
        server,
        clientId,
        clientMetadata,
        client.PrivateKeyJwt(key,{[client.modifyAssertion]:(header,payload)=>{
            payload.aud='xxx'
            }}),
        {
            [client.customFetch]:  (...args) => {
                // @ts-ignore
                return undici.fetch(args[0], { ...args[1], dispatcher: envHttpProxyAgent }) // prettier-ignore
            }
        }
    )
    let tokenEndpointResponse = await client.clientCredentialsGrant(config,
        'oidauth',
        'resource'
    )
})()

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const b64 = pem
        .replace(/-----[^-]+-----/g, '')
        .replace(/\s+/g, '');
    const binary = Buffer.from(b64, 'base64');
    return binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength);
}

async function importPrivateKey(pemFilePath: string) {
    const pem = readFileSync(pemFilePath, 'utf8');
    const keyData = pemToArrayBuffer(pem);

    return await subtle.importKey(
        'pkcs8', // PKCS#8 private key
        keyData,
        {
            name: 'RSASSA-PKCS1-v1_5', // or "RSA-PSS" depending on your key/algorithm
            hash: 'SHA-256',
        },
        false, // extractable: false for security
        ['sign']
    );
}
