// index.js

// ##################################################################
// #  Simple Node.js App to get an Access Token from BdP ADFS       #
// #  using Signed JWT Authentication                               #
// ##################################################################
//
// This application demonstrates the OAuth 2.0 Client Credentials Flow
// with the Banco de Portugal's ADFS OpenID Connect provider, using
// private_key_jwt for client authentication.
//
// Pre-requisites:
// 1. Node.js installed on your machine.
// 2. You must have registered your application with Banco de Portugal
//    to obtain a Client ID and have registered your public key.
// 3. You need to generate an RSA private/public key pair.
//
// How to generate a key pair (using OpenSSL):
// # Generate a 2048-bit RSA private key
// openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
//
// # Extract the public key from the private key
// openssl rsa -pubout -in private.key -out public.key
//
// You must provide the `public.key` to Banco de Portugal for your client registration.
// The `private.key` file must be in the same directory as this script.
//
// How to run this application:
// 1. Save this file as `index.js`.
// 2. Create a `package.json` file in the same directory:
//    npm init -y
// 3. Install the required dependencies:
//    npm install express openid-client jose
// 4. Replace the placeholder value for `clientId` with your actual Client ID.
// 5. Place your `private.key` file in the same directory.
// 6. Run the application:
//    node index.js
// 7. Open your web browser and navigate to http://localhost:3000/get-token
//    to trigger the access token request.

const express = require('express');
const { Issuer } = require('openid-client');
const fs = require('fs');
const jose = require('jose');

const app = express();
const port = 3000;

// --- Configuration ---
// The issuer URL for Banco de Portugal's ADFS OIDC configuration.
const bdpIssuerUrl = 'https://sts-cert.bportugal.net/adfs';
const privateKeyPath = './private.key';

// --- IMPORTANT ---
// Replace this with the actual Client ID for your application.
const clientId = 'YOUR_CLIENT_ID'; // <-- Replace with your Client ID

// This is the main function to get the token
async function getAccessToken() {
    try {
        console.log('Discovering OIDC configuration...');
        // Discover the issuer's metadata from the .well-known endpoint
        const bdpIssuer = await Issuer.discover(bdpIssuerUrl);
        console.log('Discovered issuer: %s', bdpIssuer.issuer);
        console.log('Token endpoint: %s', bdpIssuer.token_endpoint);

        // Load the private key from the file system
        const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
        // Import the PEM-encoded key into a JWK (JSON Web Key) format
        const jwk = await jose.importPKCS8(privateKeyPem, 'RS256');

        // It's good practice to assign a Key ID (kid) to your keys.
        // This ID should be known to the authorization server.
        jwk.kid = 'my-signing-key-01';

        // Create a client instance configured for private_key_jwt authentication
        const client = new bdpIssuer.Client({
            client_id: clientId,
            token_endpoint_auth_method: 'private_key_jwt',
        }, {
            // Provide the key set for signing the JWT assertion
            keys: [jwk]
        });

        console.log('Requesting access token using client credentials and JWT assertion...');
        // Perform the client credentials grant.
        // openid-client will automatically create and sign the client_assertion JWT.
        const tokenSet = await client.grant({
            grant_type: 'client_credentials',
            // You might need to specify a scope depending on the API you want to access.
            // Consult the Banco de Portugal API documentation for required scopes.
            // scope: 'openid profile',
        });

        console.log('Access token received!');
        return tokenSet;

    } catch (error) {
        console.error('Error getting access token:', error);
        // It's useful to log the full error, especially the body of the
        // response from the server which often contains more details.
        if (error.response) {
            console.error('Error response body:', error.response.body.toString());
        }
        throw error;
    }
}

// --- Express Route ---
// We create a simple web server to trigger the token request.
app.get('/get-token', async (req, res) => {
    if (clientId === 'YOUR_CLIENT_ID') {
        return res.status(400).send('<h1>Configuration Needed</h1><p>Please replace the placeholder <code>YOUR_CLIENT_ID</code> in the <code>index.js</code> file with your actual client ID.</p>');
    }

    if (!fs.existsSync(privateKeyPath)) {
        return res.status(400).send(`<h1>Configuration Needed</h1><p>Private key file not found at <code>${privateKeyPath}</code>. Please generate a key pair and place the private key in the correct location.</p>`);
    }

    try {
        const tokenSet = await getAccessToken();
        // For demonstration purposes, we'll display the token in the browser.
        // In a real application, you would use this token to make API calls.
        res.send(`
            <h1>Access Token Received</h1>
            <p><strong>Access Token:</strong></p>
            <pre style="background-color: #f0f0f0; padding: 10px; border-radius: 5px; word-wrap: break-word;">${tokenSet.access_token}</pre>
            <p><strong>Expires at:</strong> ${new Date(tokenSet.expires_at * 1000)}</p>
            <hr>
            <h2>Full TokenSet:</h2>
            <pre style="background-color: #f0f0f0; padding: 10px; border-radius: 5px;">${JSON.stringify(tokenSet, null, 2)}</pre>
        `);
    } catch (error) {
        res.status(500).send(`<h1>Error</h1><p>Failed to get access token.</p><pre>${error.message}</pre>`);
    }
});

app.get('/', (req, res) => {
    res.send('<h1>BdP ADFS OIDC Client (JWT Auth)</h1><p>Navigate to <a href="/get-token">/get-token</a> to request an access token.</p>');
});


// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log('Open your browser and navigate to http://localhost:3000/get-token');
});
