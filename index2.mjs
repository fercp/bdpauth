const express = require('express');
const { discovery, buildAuthorizationUrl, authorizationCodeGrant, clientCredentialsGrant, introspection, revocation } = require('openid-client');
const { SignJWT } = require('jose');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Configuration
const CONFIG = {
    issuer: 'https://your-issuer.com', // Replace with your OpenID issuer
    clientId: 'your-client-id', // Replace with your client ID
    privateKeyPath: './private-key.pem', // Path to your private key file
    audience: 'https://your-audience.com', // Replace with your audience
    scope: 'openid profile email',
    keyId: 'your-key-id' // Optional: specify key ID if needed
};

class OpenIDAuthenticator {
    constructor() {
        this.issuerMetadata = null;
        this.privateKey = null;
        this.clientMetadata = {
            client_id: CONFIG.clientId,
            token_endpoint_auth_method: 'private_key_jwt',
            token_endpoint_auth_signing_alg: 'RS256'
        };
    }

    async initialize() {
        try {
            // Load private key
            const pfx = fs.readFileSync(pfxPath);
            const p12Asn1 = forge.asn1.fromDer(pfx.toString('binary'));
            const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, pfxPassword);

            let certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
            let keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];

            const certificate = forge.pki.certificateToPem(certBag.cert);
            const privateKey = forge.pki.privateKeyToPem(keyBag.key);

// Get SHA-1 thumbprint of the cert (Key Identifier)
            const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes();
            const sha1 = forge.md.sha1.create();
            sha1.update(certDer);
            const kid = sha1.digest().toHex().toUpperCase();
            //
            //  OpenID issuer metadata
            console.log('Discovering OpenID issuer...');
            this.issuerMetadata = await discovery(new URL(CONFIG.issuer));

            console.log('OpenID client initialized successfully');
            console.log('Token endpoint:', this.issuerMetadata.token_endpoint);

        } catch (error) {
            console.error('Failed to initialize OpenID client:', error);
            throw error;
        }
    }

    // Create JWT assertion for client authentication
    async createJWTAssertion() {
        try {
            const now = Math.floor(Date.now() / 1000);

            const jwt = await new SignJtWT({
                iss: CONFIG.clientId,
                sub: CONFIG.clientId,
                aud: this.issuerMetadata.token_endpoint,
                jti: crypto.randomUUID(),
                exp: now + 300, // 5 minutes from now
                iat: now
            })
                .setProtectedHeader({
                    alg: 'RS256',
                    typ: 'JWT',
                    ...(CONFIG.keyId && { kid: CONFIG.keyId })
                })
                .sign(this.privateKey);

            return jwt;
        } catch (error) {
            console.error('Failed to create JWT assertion:', error);
            throw error;
        }
    }

    // Get access token using client credentials flow
    async getAccessToken() {
        try {
            const assertion = await this.createJWTAssertion();
            consol
            const tokenResponse = await clientCredentialsGrant(
                this.issuerMetadata,
                {
                    scope: CONFIG.scope,
                    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    client_assertion: assertion
                }
            );

            return {
                access_token: tokenResponse.access_token,
                token_type: tokenResponse.token_type,
                expires_in: tokenResponse.expires_in,
                scope: tokenResponse.scope,
                expires_at: tokenResponse.expires_at
            };

        } catch (error) {
            console.error('Failed to get access token:', error);
            throw error;
        }
    }

    // Get access token using authorization code flow (for user authentication)
    async getAccessTokenFromCode(code, redirectUri, codeVerifier) {
        try {
            const tokenResponse = await authorizationCodeGrant(
                this.issuerMetadata,
                this.clientMetadata,
                {
                    code,
                    redirect_uri: redirectUri,
                    code_verifier: codeVerifier
                }
            );

            return {
                access_token: tokenResponse.access_token,
                token_type: tokenResponse.token_type,
                expires_in: tokenResponse.expires_in,
                scope: tokenResponse.scope,
                id_token: tokenResponse.id_token,
                refresh_token: tokenResponse.refresh_token
            };

        } catch (error) {
            console.error('Failed to get access token from code:', error);
            throw error;
        }
    }

    // Introspect token to validate and get token info
    async introspectToken(token) {
        try {
            const assertion = await this.createJWTAssertion();

            const introspectionResponse = await introspection(
                this.issuerMetadata,
                this.clientMetadata,
                token,
                {
                    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    client_assertion: assertion
                }
            );

            return introspectionResponse;

        } catch (error) {
            console.error('Token introspection failed:', error);
            throw error;
        }
    }

    // Revoke token
    async revokeToken(token, tokenTypeHint = 'access_token') {
        try {
            const assertion = await this.createJWTAssertion();

            await revocation(
                this.issuerMetadata,
                this.clientMetadata,
                token,
                {
                    token_type_hint: tokenTypeHint,
                    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    client_assertion: assertion
                }
            );

            return { success: true };

        } catch (error) {
            console.error('Token revocation failed:', error);
            throw error;
        }
    }

    // Get user info using access token
    async getUserInfo(accessToken) {
        try {
            const response = await fetch(this.issuerMetadata.userinfo_endpoint, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();

        } catch (error) {
            console.error('Failed to get user info:', error);
            throw error;
        }
    }

    // Build authorization URL for user authentication
    buildAuthorizationUrl(redirectUri, state, codeChallenge) {
        const params = {
            client_id: CONFIG.clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: CONFIG.scope,
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        };

        return buildAuthorizationUrl(this.issuerMetadata, params);
    }
}

// Initialize authenticator
const authenticator = new OpenIDAuthenticator();

// Utility function to generate PKCE challenge
function generatePKCE() {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return { codeVerifier, codeChallenge };
}

// Routes
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        issuer: CONFIG.issuer
    });
});

app.get('/auth/metadata', (req, res) => {
    res.json({
        success: true,
        data: authenticator.issuerMetadata
    });
});

app.post('/auth/token', async (req, res) => {
    try {
        const tokenData = await authenticator.getAccessToken();
        res.json({
            success: true,
            data: tokenData
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/auth/authorize', (req, res) => {
    try {
        const { codeVerifier, codeChallenge } = generatePKCE();
        const state = crypto.randomUUID();
        const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;

        // Store PKCE and state in session/memory (in production, use proper session storage)
        req.app.locals.pkce = { codeVerifier, state };

        const authUrl = authenticator.buildAuthorizationUrl(redirectUri, state, codeChallenge);

        res.json({
            success: true,
            data: {
                authorization_url: authUrl,
                state: state
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/auth/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        const storedPKCE = req.app.locals.pkce;

        if (!code || !state) {
            return res.status(400).json({
                success: false,
                error: 'Missing code or state parameter'
            });
        }

        if (state !== storedPKCE.state) {
            return res.status(400).json({
                success: false,
                error: 'Invalid state parameter'
            });
        }

        const redirectUri = `${req.protocol}://${req.get('host')}/auth/callback`;
        const tokenData = await authenticator.getAccessTokenFromCode(code, redirectUri, storedPKCE.codeVerifier);

        // Clear stored PKCE
        delete req.app.locals.pkce;

        res.json({
            success: true,
            data: tokenData
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/auth/introspect', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(400).json({
                success: false,
                error: 'Token is required'
            });
        }

        const introspectionData = await authenticator.introspectToken(token);
        res.json({
            success: true,
            data: introspectionData
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.post('/auth/revoke', async (req, res) => {
    try {
        const { token, token_type_hint = 'access_token' } = req.body;
        if (!token) {
            return res.status(400).json({
                success: false,
                error: 'Token is required'
            });
        }

        await authenticator.revokeToken(token, token_type_hint);
        res.json({
            success: true,
            message: 'Token revoked successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/auth/userinfo', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Missing or invalid authorization header'
            });
        }

        const accessToken = authHeader.substring(7);
        const userInfo = await authenticator.getUserInfo(accessToken);

        res.json({
            success: true,
            data: userInfo
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Middleware to protect routes
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Access token required'
            });
        }

        const token = authHeader.substring(7);
        const introspectionData = await authenticator.introspectToken(token);

        if (!introspectionData.active) {
            return res.status(403).json({
                success: false,
                error: 'Token is not active'
            });
        }

        req.user = introspectionData;
        next();
    } catch (error) {
        res.status(403).json({
            success: false,
            error: 'Invalid token'
        });
    }
};

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Access granted to protected resource',
        user: req.user
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        await authenticator.initialize();

        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
            console.log(`Health check: http://localhost:${PORT}/health`);
            console.log(`Get metadata: GET http://localhost:${PORT}/auth/metadata`);
            console.log(`Get token: POST http://localhost:${PORT}/auth/token`);
            console.log(`Authorization URL: GET http://localhost:${PORT}/auth/authorize`);
            console.log(`Protected route: GET http://localhost:${PORT}/protected`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Received SIGTERM, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('Received SIGINT, shutting down gracefully');
    process.exit(0);
});

module.exports = app;