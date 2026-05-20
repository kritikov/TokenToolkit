import JWT from "./Core/JWT.js";
import Base64 from "./Core/Base64.js";

/**
 * Global entry point and unified interface for token operations.
 * Acts as a facade that orchestrates cryptographic utilities, JWT parsing, and Base64 operations.
 */
export default class TokenToolkit {

    /**
     * Parses and decodes a JSON Web Token (JWT) string.
     * Evaluates the structural integrity first, then builds an analytical JWT profile containing detailed blocks.
     * * @param {string} jwt - The raw encrypted or encoded JWT token string.
     * @returns {Object} An operation outcome block containing either a critical error string or the fully mapped JWT instance.
     */
     static decodeJWT(jwt) {
        const result = JWT.isValidInput(jwt);

        if (!result.valid) {
            return {
                valid: false,
                error: result.error
            };
        }
        else {
            return {
                valid: true,
                jwt: new JWT(jwt)
            };
        }
    }

    /**
     * Executes a comprehensive telemetry-backed decoding operation on a given text sequence.
     * Automatically handles both standard Base64 and URL-safe Base64 variants while logging execution summaries.
     * * @param {string} input - The raw encoded data string.
     * @returns {Object} Analytical UI-ready evaluation sequence containing metrics, diagnostics, and plain text.
     */
    static decodeBase64(input) {
        return Base64.decode(input);
    }

    /**
     * Compiles a plain text message string into a safe Base64 or Base64URL target stream.
     * Inject custom system directives inside the options map to strip alignment boundaries or swap alphabets.
     * * @param {string} input - The plain text content to transform.
     * @param {Object} [options={}] - Modifiers specifying compression layout (base64Url, removePadding).
     * @returns {Object} Detailed serialization schema reporting layout shifts, byte tallies, and target texts.
     */
    static encodeToBase64(input, options) {
        return Base64.encode(input, options);
    }

}