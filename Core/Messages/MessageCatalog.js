import MessageCodes from "./MessageCodes.js";
import Severity from "./Severity.js";

export default class MessageCatalog {

    static map = {

        // =========================================================
        // HEADER - STRUCTURE
        // =========================================================

        [MessageCodes.HEADER_INVALID_OBJECT]: {
            severity: Severity.CRITICAL,
            title: "Invalid header object",
            details: "The JWT header could not be parsed into a valid JSON object. This usually happens when the token structure is severely corrupted, uses invalid character encoding, or suffers from bad copy-paste truncation.",
            category: "structure"
        },

        [MessageCodes.HEADER_EMPTY]: {
            severity: Severity.CRITICAL,
            title: "Empty header",
            details: "The decoded JWT header is technically an object, but contains absolutely no metadata fields. A valid JSON Web Token must always provide at least the cryptographic algorithm parameter ('alg') in its header.",
            category: "structure"
        },

        [MessageCodes.HEADER_TOO_LARGE]: {
            severity: Severity.WARNING,
            title: "Excessive header size",
            details: "The header contains more than 25 configuration parameters. This highly atypical overhead can be a sign of advanced token bloating, security obfuscation techniques, or malicious attempts to cause Resource Exhaustion bugs.",
            category: "structure"
        },

        [MessageCodes.HEADER_UNKNOWN_RATIO]: {
            severity: Severity.LOW,
            title: "High unknown header ratio",
            details: "Over 60% of the key-value pairs inside this header are non-standard. While custom headers are valid, an excessive amount makes the token bloated and increases the risk of namespace collisions with future JWT specifications.",
            category: "structure"
        },

        // =========================================================
        // HEADER - SECURITY
        // =========================================================

        [MessageCodes.HEADER_ALG_NONE]: {
            severity: Severity.CRITICAL,
            title: "Unsigned JWT (alg=none)",
            details: "The token explicitly signals that cryptographic validation has been deactivated. This is a critical vulnerability; any client or malicious proxy can manipulate the payload contents freely since the backend server will bypass signature checking.",
            category: "security"
        },

        [MessageCodes.HEADER_ASYMMETRIC_NO_KEY_REFERENCE]: {
            severity: Severity.LOW,
            title: "Missing key reference",
            details: "An asymmetric algorithm (like RSA or ECDSA) was declared, but the header lacks identifiers like 'kid', 'jku', or 'jwk'. Without a specific key reference, the validating server might struggle to dynamically resolve which public key should verify this token.",
            category: "security"
        },

        [MessageCodes.HEADER_JWE_JWS_CONFUSION]: {
            severity: Severity.LOW,
            title: "JWE/JWS confusion",
            details: "The token header includes encryption metadata (like 'enc') while utilizing a digital signature algorithm. This mixes up JSON Web Signature (JWS) and JSON Web Encryption (JWE) rules, which can confuse strict cryptographic parsers.",
            category: "security"
        },

        [MessageCodes.HEADER_EDDSA_UNUSUAL_KEY_RESOLUTION]: {
            severity: Severity.LOW,
            title: "Unusual EdDSA key usage",
            details: "This token uses the modern EdDSA algorithm but bundles legacy X.509 certificate parameters like 'x5c' or 'x5u'. EdDSA setups are strongly recommended to utilize lightweight, flat JSON Web Keys ('jwk' or 'kid') for modern public key infrastructure lookup.",
            category: "security"
        },

        [MessageCodes.HEADER_SYMMETRIC_ALGO_EXPECTED_ASYMMETRIC]: {
            severity: Severity.CRITICAL,
            title: "Algorithm confusion risk",
            details: "The header declares a symmetric HMAC algorithm but attaches asymmetric properties like 'x5c' or 'jku'. This strongly indicates a potential Algorithm Confusion attack, where a malicious user feeds an asymmetric public key into an HMAC verification code to bypass signature validity.",
            category: "security"
        },

        // =========================================================
        // HEADER - CONFLICTS
        // =========================================================

        [MessageCodes.HEADER_CONFLICTING_JKU_JWK]: {
            severity: Severity.CRITICAL,
            title: "Conflicting key sources",
            details: "Both a JSON Web Key URL ('jku') and an inline JSON Web Key ('jwk') are declared simultaneously. To eliminate logical processing conflicts, the token architecture must rely strictly on either an external dynamic location or an inline public key structure.",
            category: "conflict"
        },

        [MessageCodes.HEADER_CONFLICTING_X5C_JWK]: {
            severity: Severity.LOW,
            title: "Conflicting certificate sources",
            details: "The header concurrently bundles a raw public cryptographic key ('jwk') and an X.509 certificate chain ('x5c'). This redundant approach can spark critical parser ambiguities regarding which asset holds ultimate authority for verifying the signature.",
            category: "conflict"
        },

        [MessageCodes.HEADER_KEY_RESOLUTION_AMBIGUITY]: {
            severity: Severity.LOW,
            title: "Key resolution ambiguity",
            details: "An external complex key asset resource tracker ('jku', 'x5u' or 'x5c') is defined, but no Key ID ('kid') parameter is present. Applications validating this token cannot target a single key within those external stores, resulting in slower lookups.",
            category: "conflict"
        },

        [MessageCodes.HEADER_NON_STANDARD_CTY]: {
            severity: Severity.INFO,
            title: "Non-standard content type",
            details: "The Content Type ('cty') metadata parameter is defined but is not explicitly set to 'JWT'. This parameter should only be utilized in advanced nested token scenarios (like an encrypted token nesting a signed token) to signal internal parsing requirements.",
            category: "metadata"
        },

        // =========================================================
        // HEADER - CRIT
        // =========================================================

        [MessageCodes.HEADER_CRIT_NOT_ARRAY]: {
            severity: Severity.CRITICAL,
            title: "Invalid crit format",
            details: "The mandatory extensions parameter ('crit') was found but its structure is incorrect. Per the JWT RFC 7515 specification, the 'crit' header parameter must strictly exist as a JSON array listing the string names of custom extension elements.",
            category: "crit"
        },

        [MessageCodes.HEADER_CRIT_EMPTY]: {
            severity: Severity.LOW,
            title: "Empty crit array",
            details: "The 'crit' array parameter is present in the header metadata list but it contains absolutely zero elements. This creates redundant overhead inside the JSON structure without triggering any actual critical parameter checking logic.",
            category: "crit"
        },

        [MessageCodes.HEADER_CRIT_NON_STRING]: {
            severity: Severity.CRITICAL,
            title: "Invalid crit entry",
            details: "The 'crit' parameter array contains numbers, booleans, objects or null types. The specification states that the critical array must contain strictly string names that precisely map to other custom parameters defined inside the token header.",
            category: "crit"
        },

        [MessageCodes.HEADER_CRIT_UNKNOWN_FIELDS]: {
            severity: Severity.CRITICAL,
            title: "Unknown crit reference",
            details: "The critical extension array ('crit') demands enforcement for parameters that are completely missing from the header. The validating engine is required by specification rules to instantly reject this token because it cannot process these hidden requirements.",
            category: "crit"
        },

        [MessageCodes.HEADER_CRIT_NON_STANDARD_FIELDS]: {
            severity: Severity.LOW,
            title: "Non-standard crit fields",
            details: "The critical extension array ('crit') contains references targeting custom parameters rather than standard global specifications. Ensure your backend verification application actually features custom code plugins capable of evaluating these specific headers.",
            category: "crit"
        },

        // =========================================================
        // HEADER - URLS
        // =========================================================

        [MessageCodes.HEADER_INVALID_URL]: {
            severity: Severity.WARNING,
            title: "Invalid URL",
            details: "A critical remote infrastructure metadata parameter (such as 'jku' or 'x5u') contains a corrupted or malformed web address string. Token verification engines will crash or fail instantly when attempting to process or parse this URL.",
            category: "url"
        },

        [MessageCodes.HEADER_NON_HTTPS_URL]: {
            severity: Severity.WARNING,
            title: "Non-HTTPS URL",
            details: "The remote key locator URL uses the unencrypted HTTP protocol. This represents a massive flaw; an attacker on the same network could perform a Man-In-The-Middle (MITM) attack, intercept the request, and inject fake public keys to forge valid tokens.",
            category: "url"
        },

        [MessageCodes.HEADER_UNSAFE_HOST_URL]: {
            severity: Severity.WARNING,
            title: "Unsafe host",
            details: "The remote key locator URL explicitly targets localhost or an exposed numeric IP address. While acceptable in local sandbox development, this configuration must never reach production environments as it exposes internal endpoints to Server-Side Request Forgery (SSRF).",
            category: "url"
        },

        // =========================================================
        // PAYLOAD - STRUCTURE
        // =========================================================

        [MessageCodes.PAYLOAD_INVALID_OBJECT]: {
            severity: Severity.CRITICAL,
            title: "Invalid payload",
            details: "The decoded data payload segment fails to compile into a structurally sound JSON object. This usually stems from character corruption during transit, transmission truncations, or deep base64url data block processing errors.",
            category: "structure"
        },

        [MessageCodes.PAYLOAD_EMPTY]: {
            severity: Severity.CRITICAL,
            title: "Empty payload",
            details: "The JWT payload decoded successfully but contains zero internal claims or attributes. Tokens must pack relevant claims (such as authorization scopes, user IDs, or lifetimes) to serve any logical identity or permissions purpose.",
            category: "structure"
        },

        [MessageCodes.PAYLOAD_TOO_LARGE]: {
            severity: Severity.WARNING,
            title: "Large payload",
            details: "The data payload segment contains an excessive count of claims (more than 25 attributes). Storing monolithic data schemas, excessive permissions arrays, or user profiles inside a client-side cookie/token creates substantial HTTP transit bandwidth overhead.",
            category: "structure"
        },

        [MessageCodes.PAYLOAD_UNKNOWN_RATIO]: {
            severity: Severity.LOW,
            title: "Mostly custom claims",
            details: "A dominant portion of this token's payload relies entirely on custom business parameters instead of standard IANA JSON Web Token claims. Consider auditing names to ensure they do not clash with standard definitions (like 'iss', 'sub', 'aud').",
            category: "structure"
        },

        // =========================================================
        // PAYLOAD - CLAIMS
        // =========================================================

        [MessageCodes.PAYLOAD_MISSING_SUB]: {
            severity: Severity.LOW,
            title: "Missing subject",
            details: "The identity subject claim ('sub') is absent. Although technically optional under standard RFC guidelines, omitting the unique user ID or client identifier limits the utility of access tokens within microservices architectures.",
            category: "claims"
        },

        [MessageCodes.PAYLOAD_MISSING_ISS]: {
            severity: Severity.LOW,
            title: "Missing issuer",
            details: "The authorization domain identifier claim ('iss') is missing. Without this string parameter, backend API gateways cannot verify which security authority or authentication server generated and signed this credential.",
            category: "claims"
        },

        [MessageCodes.PAYLOAD_MISSING_AUD]: {
            severity: Severity.INFO,
            title: "Missing audience",
            details: "The target application claim ('aud') is missing. Audience parameters prevent token recycling attacks; without it, any downstream third-party service could intercept this token and maliciously replay it against other internal APIs.",
            category: "claims"
        },

        [MessageCodes.PAYLOAD_MISSING_EXP]: {
            severity: Severity.WARNING,
            title: "Missing expiration",
            details: "The expiration timestamp attribute ('exp') is completely missing. This leaves the token without an explicit lifespan, allowing it to remain valid indefinitely. If this token is leaked, an attacker gains permanent access unless a revocation layer is implemented.",
            category: "claims"
        },

        [MessageCodes.PAYLOAD_MISSING_IAT]: {
            severity: Severity.LOW,
            title: "Missing issued-at",
            details: "The generation timestamp parameter ('iat') is omitted. Lacking an explicit record of when this credential was issued prevents applications from tracking token age or enforcing maximum age policies.",
            category: "claims"
        },

        [MessageCodes.PAYLOAD_MISSING_NBF]: {
            severity: Severity.INFO,
            title: "Missing not-before",
            details: "The active threshold timestamp claim ('nbf') is missing. The token becomes immediately consumable upon creation. For time-sensitive tasks, adding 'nbf' ensures the token cannot be used before a specified moment.",
            category: "claims"
        },

        [MessageCodes.PAYLOAD_MISSING_JTI]: {
            severity: Severity.INFO,
            title: "Missing JWT ID",
            details: "The unique token identity number ('jti') is missing. If you need to defend against replay attacks by tracking individual tokens in a distributed cache, using a unique 'jti' identifier is essential.",
            category: "claims"
        },

        // =========================================================
        // PAYLOAD - TYPES
        // =========================================================

        [MessageCodes.PAYLOAD_INVALID_EXP_TYPE]: {
            severity: Severity.CRITICAL,
            title: "Invalid exp type",
            details: "The expiration claim ('exp') contains non-numeric characters, formatting arrays, strings, or ISO dates. The spec demands that 'exp' must strictly exist as a numeric Unix Epoch timestamp (seconds since Jan 1, 1970).",
            category: "types"
        },

        [MessageCodes.PAYLOAD_INVALID_IAT_TYPE]: {
            severity: Severity.CRITICAL,
            title: "Invalid iat type",
            details: "The generation timestamp claim ('iat') uses an invalid format. It must be written strictly as an integer tracking Unix Epoch seconds. String dates or localized time strings will cause validation components to reject the token.",
            category: "types"
        },

        [MessageCodes.PAYLOAD_INVALID_NBF_TYPE]: {
            severity: Severity.CRITICAL,
            title: "Invalid nbf type",
            details: "The activation timestamp claim ('nbf') violates formatting requirements. It must exist exclusively as a numeric Unix timestamp integer to allow servers to correctly process date comparison logic.",
            category: "types"
        },

        [MessageCodes.PAYLOAD_INVALID_AUD_TYPE]: {
            severity: Severity.CRITICAL,
            title: "Invalid audience type",
            details: "The audience definition attribute ('aud') utilizes an invalid data format type. The audience descriptor must exist either as a single flat string identifier or as an array containing strictly string values.",
            category: "types"
        },

        // =========================================================
        // PAYLOAD - TIME
        // =========================================================

        [MessageCodes.PAYLOAD_TOKEN_EXPIRED]: {
            severity: Severity.WARNING,
            title: "Token expired",
            details: "The token's expiration timestamp ('exp') points to a moment in the past. API gateways and microservices must block access immediately upon encountering an expired token to maintain application security.",
            category: "time"
        },

        [MessageCodes.PAYLOAD_IAT_IN_FUTURE]: {
            severity: Severity.WARNING,
            title: "Issued in future",
            details: "The creation timestamp ('iat') points to a future date. This indicates a severe clock desynchronization between your authorization servers and the API backend, or an intentional modification of token time metrics.",
            category: "time"
        },

        [MessageCodes.PAYLOAD_TIME_TOO_FAR_IN_PAST]: {
            severity: Severity.WARNING,
            title: "Legacy issue date",
            details: "The creation date claim ('iat') points to a time several years in the past. Even if the token has an exceptionally long expiration window, consuming such old tokens increases the risk of replaying compromised credentials.",
            category: "time"
        },

        [MessageCodes.PAYLOAD_TOKEN_NOT_ACTIVE]: {
            severity: Severity.WARNING,
            title: "Token not active",
            details: "The activation timestamp threshold ('nbf') sits in the future. This token is currently in a pre-active cooling window and cannot be legally accepted by server validation applications until the timestamp passes.",
            category: "time"
        },

        // =========================================================
        // PAYLOAD - CONSISTENCY
        // =========================================================

        [MessageCodes.PAYLOAD_EXP_BEFORE_IAT]: {
            severity: Severity.CRITICAL,
            title: "Invalid time order",
            details: "The expiration timestamp ('exp') is chronologically earlier than the creation timestamp ('iat'). This logical error invalidates the lifespan calculation and typically signals a programming error in the token factory configuration.",
            category: "consistency"
        },

        [MessageCodes.PAYLOAD_NBF_BEFORE_IAT]: {
            severity: Severity.LOW,
            title: "Suspicious time order",
            details: "The token claims it becomes active ('nbf') before it was actually generated ('iat'). While it doesn't cause validation failures, this chronological inconsistency points to unoptimized or flawed timestamp logic in the authorization system.",
            category: "consistency"
        },

        [MessageCodes.PAYLOAD_NBF_AFTER_EXP]: {
            severity: Severity.CRITICAL,
            title: "Impossible time window",
            details: "The activation threshold date ('nbf') is set to occur after the expiration date ('exp'). This logical contradiction renders the token permanently unusable, as it expires before it can legally become active.",
            category: "consistency"
        },

        // =========================================================
        // PAYLOAD - SECURITY
        // =========================================================

        [MessageCodes.PAYLOAD_UNSIGNED_WITH_EXP]: {
            severity: Severity.LOW,
            title: "Unsigned token with expiration",
            details: "The token defines an expiration threshold ('exp') but features no digital signature. Without a signature layer, the expiration value can be easily extended by a client or proxy, making the expiration claim untrustworthy.",
            category: "security"
        },

        [MessageCodes.PAYLOAD_HMAC_ARRAY_AUD]: {
            severity: Severity.LOW,
            title: "Unusual audience format",
            details: "An HMAC symmetric algorithm token features an audience listing packaged as an array. Array-based audiences are typical for multi-service public key environments, whereas symmetric setups generally target single, dedicated backends via a flat string.",
            category: "security"
        },

        [MessageCodes.PAYLOAD_EXTREME_LIFETIME]: {
            severity: Severity.WARNING,
            title: "Extreme lifetime",
            details: "The calculated lifespan between creation ('iat') and expiration ('exp') exceeds 10 years. Tokens with long lifespans amplify security risks because they remain valid even if user permissions change or systems are compromised.",
            category: "security"
        },

        // =========================================================
        // PAYLOAD - CONTEXT
        // =========================================================

        [MessageCodes.PAYLOAD_UNSIGNED_IDENTITY]: {
            severity: Severity.CRITICAL,
            title: "Unsigned identity token",
            details: "This unsigned token carries sensitive user identification attributes. Transporting real identities or access scopes without cryptographic validation allows any party to easily impersonate administrative profiles.",
            category: "context"
        },

        [MessageCodes.PAYLOAD_NON_STANDARD_SUB]: {
            severity: Severity.INFO,
            title: "Non-standard subject format",
            details: "The unique subject identifier ('sub') contains complex nested JSON properties instead of a flat string. While functional, passing complex nested models within the subject claim can break compatibility with strict standard identity microservices.",
            category: "context"
        },

        [MessageCodes.PAYLOAD_SENSITIVE_DATA_EXPOSURE]: {
            severity: Severity.WARNING,
            title: "Sensitive data exposure",
            details: "The payload appears to expose highly sensitive cleartext values (like strings resembling passwords, private keys, or hashes). JWT payloads are merely base64url encoded, not encrypted, meaning anyone can read these values.",
            category: "context"
        },

        // =========================================================
        // SIGNATURE - STRUCTURE
        // =========================================================

        [MessageCodes.SIGNATURE_ALG_NONE_WITH_SIGNATURE]: {
            severity: Severity.CRITICAL,
            title: "Invalid signature for alg=none",
            details: "The token header specifies 'alg=none' but includes a cryptographic signature block. This structural contradiction can confuse verification engines, potentially leading to security workarounds or parser bypass vulnerabilities.",
            category: "structure"
        },

        [MessageCodes.SIGNATURE_MISSING]: {
            severity: Severity.CRITICAL,
            title: "Missing signature",
            details: "The header specifies a digital signing algorithm, but the signature segment is missing. The token cannot be cryptographically verified and must be rejected as an unauthenticated payload.",
            category: "structure"
        },

        [MessageCodes.SIGNATURE_WHITESPACE_OUTER]: {
            severity: Severity.CRITICAL,
            title: "Signature whitespace (outer)",
            details: "The signature block includes leading or trailing whitespace characters. These padding anomalies break the continuous base64url data stream, causing parsing methods to fail during verification routines.",
            category: "structure"
        },

        [MessageCodes.SIGNATURE_WHITESPACE_INTERNAL]: {
            severity: Severity.CRITICAL,
            title: "Signature whitespace (internal)",
            details: "Hidden space or line break characters were detected inside the signature block. This internal formatting corruption violates base64url guidelines and prevents cryptographic validation functions from processing the signature.",
            category: "structure"
        },

        [MessageCodes.STRUCTURE_TRAILING_DOT]: {
            severity: Severity.CRITICAL,
            title: "Trailing separator",
            details: "The token string ends with a trailing period. This layout error often occurs during manual copy-paste actions, misinterpreting the signature boundaries and breaking the token structure.",
            category: "structure"
        },

        [MessageCodes.SIGNATURE_TOO_SHORT]: {
            severity: Severity.WARNING,
            title: "Short signature",
            details: "The signature length is unusually short for the declared algorithm. This indicates a truncated string or a signature block modified by a client, rendering cryptographic verification impossible.",
            category: "structure"
        },

        // =========================================================
        // SIGNATURE - ENCODING
        // =========================================================

        [MessageCodes.SIGNATURE_INVALID_BASE64URL]: {
            severity: Severity.CRITICAL,
            title: "Invalid base64url encoding",
            details: "The signature segment contains characters outside the valid base64url character set. The block must consist exclusively of alphanumeric characters, hyphens, and underscores.",
            category: "encoding"
        },

        [MessageCodes.SIGNATURE_INVALID_CHARS]: {
            severity: Severity.CRITICAL,
            title: "Invalid signature characters",
            details: "The signature block contains classic base64 characters like '+' or '/'. Tokens must use the web-safe base64url format, which swaps these characters for hyphens and underscores to prevent URL transmission corruption.",
            category: "encoding"
        },

        [MessageCodes.SIGNATURE_HAS_PADDING]: {
            severity: Severity.WARNING,
            title: "Unexpected padding in signature",
            details: "The signature segment concludes with '=' padding characters. Standard token implementations omit trailing padding symbols to optimize performance and prevent string routing issues in web environments.",
            category: "encoding"
        },

        [MessageCodes.SIGNATURE_DECODE_FAILED]: {
            severity: Severity.CRITICAL,
            title: "Signature decode failed",
            details: "The verification system failed to decode the base64url stream into a raw byte array. This points to data corruption within the signature block, making authentication verification impossible.",
            category: "encoding"
        },

        // =========================================================
        // SIGNATURE - LENGTH
        // =========================================================

        [MessageCodes.SIGNATURE_UNEXPECTED_LENGTH]: {
            severity: Severity.WARNING,
            title: "Unexpected signature length",
            details: "The signature's byte length does not match the output size required by the selected algorithm. This mismatch indicates a bad signature block generation or an intentional manipulation of algorithm attributes.",
            category: "length"
        },

        [MessageCodes.SIGNATURE_TOO_LARGE]: {
            severity: Severity.WARNING,
            title: "Excessive signature size",
            details: "The signature segment's size exceeds 4096 bytes. Signatures are typically compact hash allocations; excessively large segments consume memory resources and can trigger Denials of Service (DoS) in validation applications.",
            category: "length"
        },            

        // =========================================================
        // SIGNATURE - CONSISTENCY
        // =========================================================

        [MessageCodes.SIGNATURE_RSA_TOO_SMALL]: {
            severity: Severity.WARNING,
            title: "RSA signature too small",
            details: "The decoded RSA signature block falls short of the 128-byte security threshold. This suggests the use of weak, short key sizes (under 1024 bits) that are highly vulnerable to modern brute-force decryption attacks.",
            category: "consistency"
        },

        [MessageCodes.SIGNATURE_PSS_TOO_SMALL]: {
            severity: Severity.WARNING,
            title: "RSA-PSS signature too small",
            details: "The modern RSA-PSS signature block contains fewer than 128 bytes. This indicates the underlying cryptographic key length is weak, failing to meet corporate public key infrastructure safety recommendations.",
            category: "consistency"
        },

        // =========================================================
        // SIGNATURE - SECURITY
        // =========================================================

        [MessageCodes.SIGNATURE_LOW_ENTROPY]: {
            severity: Severity.WARNING,
            title: "Low entropy signature",
            details: "The signature byte density displays unusually low randomness (entropy). Cryptographic signatures must feature high variance; low entropy suggests a flawed key generation process or a mocked signature value.",
            category: "security"
        },

        [MessageCodes.SIGNATURE_HMAC_TOO_LARGE]: {
            severity: Severity.LOW,
            title: "Large HMAC signature",
            details: "The symmetric HMAC signature block size is larger than 128 bytes. Standard HMAC validations yield compact allocations, so an oversized layout may point to unoptimized coding routines or misconfigured parameters.",
            category: "security"
        },

        // =========================================================
        // SIGNATURE - HEURISTICS
        // =========================================================

        [MessageCodes.SIGNATURE_REPEATING_CHARS]: {
            severity: Severity.WARNING,
            title: "Low-variance signature",
            details: "The signature segment includes repetitive character sequences. Authentic cryptographic operations output high-entropy randomness; repeating blocks indicate a placeholder signature or string manipulation.",
            category: "heuristics"
        }
    };
}