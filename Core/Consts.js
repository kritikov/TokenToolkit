import Severity from "./Messages/Severity.js";

export default class Consts{

    static StandardHeaders = {

        alg: {
            name: "alg",
            description: "Algorithm used to sign or secure the JWT",
            type: "string",
            required: true,
            critical: true,
            category: "security",
            examples: ["HS256", "RS256", "ES256", "EdDSA"]
        },

        typ: {
            name: "typ",
            description: "Type of token. Usually set to 'JWT' to indicate a JSON Web Token",
            type: "string",
            required: false,
            critical: false,
            category: "metadata",
            examples: ["JWT"]
        },

        cty: {
            name: "cty",
            description: "Content type of the payload. Commonly used when nesting JWTs",
            type: "string",
            required: false,
            critical: false,
            category: "metadata",
            examples: ["JWT", "application/json"]
        },

        kid: {
            name: "kid",
            description: "Key ID used to identify which key should be used to verify the signature",
            type: "string",
            required: false,
            critical: true,
            category: "security",
            examples: ["key-1", "prod-signing-key"]
        },

        jku: {
            name: "jku",
            description: "URL pointing to a JSON Web Key Set (JWKS) containing public verification keys",
            type: "string (url)",
            required: false,
            critical: true,
            category: "security",
            examples: [
                "https://auth.example.com/.well-known/jwks.json"
            ]
        },

        jwk: {
            name: "jwk",
            description: "Embedded JSON Web Key containing the public key directly inside the header",
            type: "object",
            required: false,
            critical: true,
            category: "security",
            examples: [
                "{ kty: 'RSA', n: '...', e: 'AQAB' }"
            ]
        },

        x5u: {
            name: "x5u",
            description: "URL pointing to the X.509 certificate or certificate chain used for verification",
            type: "string (url)",
            required: false,
            critical: true,
            category: "certificate",
            examples: [
                "https://example.com/certs/public.pem"
            ]
        },

        x5c: {
            name: "x5c",
            description: "X.509 certificate chain used to validate the token signature",
            type: "string[]",
            required: false,
            critical: true,
            category: "certificate",
            examples: [
                "[MIIC..., MIID...]"
            ]
        },

        x5t: {
            name: "x5t",
            description: "SHA-1 thumbprint of the X.509 certificate",
            type: "string",
            required: false,
            critical: false,
            category: "certificate",
            examples: ["abc123thumbprint"]
        },

        "x5t#S256": {
            name: "x5t#S256",
            description: "SHA-256 thumbprint of the X.509 certificate",
            type: "string",
            required: false,
            critical: false,
            category: "certificate",
            examples: ["sha256-thumbprint"]
        },

        crit: {
            name: "crit",
            description: "List of header parameters that must be understood and processed by the JWT consumer",
            type: "string[]",
            required: false,
            critical: true,
            category: "security",
            examples: [["exp", "custom-security-extension"]]
        },

        zip: {
            name: "zip",
            description: "Compression algorithm applied to the payload before signing/encryption",
            type: "string",
            required: false,
            critical: false,
            category: "compression",
            examples: ["DEF"]
        },

        enc: {
            name: "enc",
            description: "Content encryption algorithm used for JWE tokens",
            type: "string",
            required: false,
            critical: true,
            category: "encryption",
            examples: ["A256GCM", "A128CBC-HS256"]
        },

        epk: {
            name: "epk",
            description: "Ephemeral public key used in key agreement algorithms",
            type: "object",
            required: false,
            critical: true,
            category: "encryption",
            examples: [
                "{ kty: 'EC', crv: 'P-256', x: '...', y: '...' }"
            ]
        },

        apu: {
            name: "apu",
            description: "Agreement PartyUInfo — identifies one party in key agreement",
            type: "string",
            required: false,
            critical: false,
            category: "encryption",
            examples: ["client-application"]
        },

        apv: {
            name: "apv",
            description: "Agreement PartyVInfo — identifies the other party in key agreement",
            type: "string",
            required: false,
            critical: false,
            category: "encryption",
            examples: ["authorization-server"]
        },

        iv: {
            name: "iv",
            description: "Initialization vector used during encryption",
            type: "string",
            required: false,
            critical: true,
            category: "encryption",
            examples: ["AxY8DCtDaGlsbGljb3RoZQ"]
        },

        tag: {
            name: "tag",
            description: "Authentication tag ensuring encrypted content integrity",
            type: "string",
            required: false,
            critical: true,
            category: "encryption",
            examples: ["Mz-VPPyU4RlcuYv1IwIvzw"]
        },

        nonce: {
            name: "nonce",
            description: "Unique random value used to prevent replay attacks",
            type: "string",
            required: false,
            critical: true,
            category: "security",
            examples: ["n-0S6_WzA2Mj"]
        }
    };
    
    static ValidAlgorithms = [
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
        "EdDSA",
        "none"
    ];

    static AlgorithmInfo = {

        // HMAC
        HS256: {
            family: "HMAC",
            hash: "SHA-256",
            type: "symmetric",
            securityLevel: "recommended"
        },

        HS384: {
            family: "HMAC",
            hash: "SHA-384",
            type: "symmetric",
            securityLevel: "strong"
        },

        HS512: {
            family: "HMAC",
            hash: "SHA-512",
            type: "symmetric",
            securityLevel: "strong"
        },

        // RSA
        RS256: {
            family: "RSA",
            hash: "SHA-256",
            type: "asymmetric",
            securityLevel: "recommended"
        },

        RS384: {
            family: "RSA",
            hash: "SHA-384",
            type: "asymmetric",
            securityLevel: "strong"
        },

        RS512: {
            family: "RSA",
            hash: "SHA-512",
            type: "asymmetric",
            securityLevel: "strong"
        },

        // RSA-PSS
        PS256: {
            family: "RSA-PSS",
            hash: "SHA-256",
            type: "asymmetric",
            securityLevel: "preferred"
        },

        PS384: {
            family: "RSA-PSS",
            hash: "SHA-384",
            type: "asymmetric",
            securityLevel: "preferred"
        },

        PS512: {
            family: "RSA-PSS",
            hash: "SHA-512",
            type: "asymmetric",
            securityLevel: "preferred"
        },

        // ECDSA
        ES256: {
            family: "ECDSA",
            hash: "SHA-256",
            type: "asymmetric",
            securityLevel: "preferred"
        },

        ES384: {
            family: "ECDSA",
            hash: "SHA-384",
            type: "asymmetric",
            securityLevel: "preferred"
        },

        ES512: {
            family: "ECDSA",
            hash: "SHA-512",
            type: "asymmetric",
            securityLevel: "preferred"
        },

        // Edwards-curve
        EdDSA: {
            family: "EdDSA",
            hash: "Ed25519 / Ed448",
            type: "asymmetric",
            securityLevel: "modern"
        },

        // unsigned
        none: {
            family: "Unsigned",
            hash: null,
            type: "unsigned",
            securityLevel: "unsafe"
        }
    };

    static StandardClaims = {

        sub: {
            name: "sub",
            info: "Unique identifier of the principal (user, client, or service) encoded in the token.",
            type: "string",
            category: "identity",
            required: false,
            critical: false,
        },

        iss: {
            name: "iss",
            info: "The security authority, domain, or identity provider that generated and signed the token.",
            type: "string",
            category: "security",
            required: false,
            critical: false,
        },

        aud: {
            name: "aud",
            info: "The specific application, API, or resource server(s) authorized to accept this token.",
            type: "string | string[]",
            category: "security",
            required: false,
            critical: false,
        },

        exp: {
            name: "exp",
            info: "Hard lifespan threshold; the token becomes strictly invalid and rejected after this moment.",
            type: "number (unix timestamp)",
            category: "time",
            required: false,
            critical: true,
        },

        iat: {
            name: "iat",
            info: "Cryptographic creation timestamp, used to calculate token age and enforce maximum session limits.",
            type: "number (unix timestamp)",
            category: "time",
            required: false,
            critical: false,
        },

        nbf: {
            name: "nbf",
            info: "Activation floor; defines a pre-active cooling window during which the token cannot be used.",
            type: "number (unix timestamp)",
            category: "time",
            required: false,
            critical: false,
        },

        jti: {
            name: "jti",
            info: "A unique token ID utilized to prevent replay attacks and track server-side revocation lists.",
            type: "string",
            category: "security",
            required: false,
            critical: false,
        }
    };

}