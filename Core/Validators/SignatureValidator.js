import Base64 from "../Base64.js";
import Message from "../Messages/Message.js";
import Severity from "../Messages/Severity.js";
import MessageCodes from "../Messages/MessageCodes.js";

export default class SignatureValidator {

    static validate(signatureText, header) {

        const messages = [];

        messages.push(...SignatureValidator.#validateStructure(signatureText, header));
        messages.push(...SignatureValidator.#validateEncoding(signatureText));
        messages.push(...SignatureValidator.#validateAlgorithmConsistency(signatureText, header));
        messages.push(...SignatureValidator.#validateLengths(signatureText, header));
        messages.push(...SignatureValidator.#validateSecurity(signatureText, header));

        return messages;
    }

    static #validateStructure(signatureText, header) {

        const messages = [];
        const algorithm = header?.display?.algorithm;

        // alg=none MUST NOT contain signature
        if (algorithm?.key === "none") {

            if (signatureText.length > 0) {
                messages.push(new Message({code: MessageCodes.SIGNATURE_ALG_NONE_WITH_SIGNATURE}));
            }

            return messages;
        }

        // signed JWT without signature
        if (signatureText.length === 0) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_MISSING}));
            return messages;
        }

        // whitespace corruption
        if (signatureText !== signatureText.trim()) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_WHITESPACE_OUTER}));
        }

        // internal whitespace
        if (/\s/.test(signatureText)) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_WHITESPACE_INTERNAL}));
        }

        // suspiciously short
        if (signatureText.length < 10) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_TOO_SHORT}));
        }

        // trailing characters
        if (signatureText.endsWith('.')) {
            messages.push(new Message({code: MessageCodes.STRUCTURE_TRAILING_DOT}));
        }

        return messages;
    }

    static #validateEncoding(signatureText) {

        const messages = [];

        if (!signatureText) {
            return messages;
        }

        // invalid base64url chars
        if (!/^[A-Za-z0-9\-_]+$/.test(signatureText)) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_INVALID_BASE64URL}));
        }

        // forbidden chars
        if (/[+/]/.test(signatureText)) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_INVALID_CHARS}));
        }

        // JWT should not contain =
        if (signatureText.includes("=")) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_HAS_PADDING}));
        }

        // decode validation
        try {
            Base64.urlToBytes(signatureText);
        }
        catch {
            messages.push(new Message({code: MessageCodes.SIGNATURE_DECODE_FAILED}));
        }

        return messages;
    }

    static #validateAlgorithmConsistency(signatureText, header) {

        const messages = [];
        const algorithm = header?.display?.algorithm;

        if (!algorithm || !signatureText) {
            return messages;
        }

        let bytes;

        try {
            bytes = Base64.urlToBytes(signatureText);
        }
        catch {
            return messages;
        }

        const byteLength = bytes.length;

        // RSA signatures are usually large
        if (algorithm?.family == "RSA" && byteLength < 128) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_RSA_TOO_SMALL}));
        }

        // PS signatures are also RSA-based
        if (algorithm?.family == "RSA-PSS" && byteLength < 128) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_PSS_TOO_SMALL}));
        }

        return messages;
    }

    static #validateLengths(signatureText, header) {

        const messages = [];
        const algorithm = header?.display?.algorithm;

        if (!algorithm || !signatureText) {
            return messages;
        }

        let bytes;

        try {
            bytes = bytes = Base64.urlToBytes(signatureText);
        }
        catch {
            return messages;
        }

        const byteLength = bytes.length;

        const expectedLengths = {
            HS256: 32,
            HS384: 48,
            HS512: 64,

            ES256: 64,
            ES384: 96,
            ES512: 132,

            EdDSA: 64
        };

        const expected = expectedLengths[algorithm.key];

        // exact-length algorithms
        if (expected && byteLength !== expected) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_UNEXPECTED_LENGTH}));
        }

        // very large signature
        if (byteLength > 4096) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_TOO_LARGE}));
        }

        return messages;
    }

    static #validateSecurity(signatureText, header) {

        const messages = [];
        const algorithm = header?.display?.algorithm;

        if (!algorithm || !signatureText) {
            return messages;
        }

        let bytes;

        try {
            bytes = Base64.urlToBytes(signatureText);
        }
        catch {
            return messages;
        }

        const byteLength = bytes.length;

        // suspiciously tiny signatures
        if (byteLength < 16) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_LOW_ENTROPY}));
        }

        // HMAC signatures too large
        if (algorithm?.family == "HMAC" && byteLength > 128) {
            messages.push(new Message({code: MessageCodes.SIGNATURE_HMAC_TOO_LARGE}));
        }

        return messages;
    }
}