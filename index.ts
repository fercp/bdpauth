import * as client from 'openid-client';
import { webcrypto } from 'crypto';
import { readFileSync } from 'fs';
const { subtle } = webcrypto;

let server!: URL
let key!: client.CryptoKey | client.PrivateKey
let clientId!: string
let clientMetadata!: Partial<client.ClientMetadata> | string | undefined

(async () => {
    server = new URL('https://sts-cert.bportugal.net/adfs/.well-known/openid-configuration');
    clientId = 'https://bpnetsvc-faitdexxx-cert.bportugal.pt/'
    clientMetadata = {
        client_id: clientId,
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256'
    }
    let envHttpProxyAgent = new undici.EnvHttpProxyAgent()

    let config!: client.Configuration

// @ts-ignore
    config[client.customFetch] = (...args) => {
        // @ts-ignore
        return undici.fetch(args[0], { ...args[1], dispatcher: envHttpProxyAgent }) // prettier-ignore
    }
    const privateKey = await importPrivateKey('./private_key.pem');
// @ts-ignore
    let config = await client.discovery(
        server,
        clientId,
        clientMetadata,
        client.PrivateKeyJwt(privateKey),
        {
            [client.customFetch]: async (url: string, options: RequestInit): Promise<Response> => {
                console.log('Fetching:', url);
                return fetch(url, {
                    ...options,
                    headers: {
                        ...options.headers,
                        'X-Custom-Header': 'example'
                    }
                });
            }
        }
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
