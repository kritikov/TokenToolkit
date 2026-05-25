import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";
import Catalog from "./Messages/Base64MessageCatalog.js";
import Codes from "./Messages/Base64MessageCodes.js";

export default class Base64 {

    // =====================================================
    // 1. SILENT CORE METHODS (Για το JWT / Utilities)
    // =====================================================
    
    /**
     * core string manipulation tool that standardizes and decodes Base64/Base64URL.
     * Silent method: Throws native errors on failure instead of logging UI messages.
     * * @param {string} value - The encoded string input.
     * @returns {string} The decoded raw binary string string.
     */
    static decodeRaw(value) {
        if (typeof value !== "string") throw new TypeError("Input must be a string");
        
        let input = value.replace(/\s/g, "");
        if (input.length === 0) return "";

        if (input.includes("-") || input.includes("_")) {
            input = input.replace(/-/g, "+").replace(/_/g, "/");
        }

        const remainder = input.length % 4;
        if (remainder === 1) throw new Error("Invalid Base64 length");
        if (remainder > 0) {
            input += "=".repeat(4 - remainder);
        }

        return atob(input);
    }

    /**
     * Decodes a Base64 or Base64URL string strictly into a validated UTF-8 text string.
     * Throws an exception if the underlying bytes do not map to valid text characters.
     * * @param {string} value - The encoded string input.
     * @returns {string} The decoded UTF-8 plain text.
     */
    static decodeToUtf8(value) {
        const binary = Base64.decodeRaw(value);
        const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
        return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }

    /**
     * Instantiates a custom diagnostic message and registers it into a given telemetry collection.
     * * @private
     */
    static #addMessage(messages, code, titleData = null, data = null){
        messages.push(new Message({code: code, data: data, titleData: titleData, catalog: Catalog}));
    }

    /**
     * Converts a Base64 or Base64URL string directly into a raw byte array (Uint8Array).
     * Ideal for cryptographic validation operations. Safe-fail: returns an empty array on corruption.
     * * @param {string} value - The encoded string input.
     * @returns {Uint8Array} The raw byte representation.
     */
    static urlToBytes(value) {
        try {
            const binary = this.decodeRaw(value);
            return Uint8Array.from(binary, c => c.charCodeAt(0));
        }
        catch {
            return new Uint8Array(0);
        }
    }

    /**
     * Normalizes the incoming user input for UI reporting.
     * Strips whitespace, detects the dialect type, repairs structure, and seeds analytical logs.
     * * @private
     */
    static #normalize(value) {

        const result = {
            valid: true,
            normalizedText: "",
            type: "base64",
            paddingFixed: false,
            messages: []
        };

        // =====================================================
        // INPUT VALIDATION
        // =====================================================

        if (typeof value !== "string") {
            result.valid = false;
            Base64.#addMessage(result.messages, Codes.INPUT_NOT_STRING);
            return result;
        }

        const originalLength = value.length;
        let input = value.replace(/\s/g, "");

        const data = `total chars: ${originalLength - input.length}`;
        if (input.length !== originalLength) {
            Base64.#addMessage(result.messages, Codes.WHITESPACE_REMOVED, null, data);
        }

        if (input.length === 0) {
            result.valid = false;
            Base64.#addMessage(result.messages, Codes.INPUT_EMPTY);
            return result;
        }

        // =====================================================
        // TYPE DETECTION
        // =====================================================

        if (input.includes("-") || input.includes("_")) {
            result.type = "base64url";
            Base64.#addMessage(result.messages, Codes.BASE64URL_DETECTED);
            input = input
                .replace(/-/g, "+")
                .replace(/_/g, "/");
        }
        else{
            Base64.#addMessage(result.messages, Codes.BASE64_DETECTED);
        }

        // =====================================================
        // PADDING FIX
        // =====================================================

        const remainder = input.length % 4;
        if (remainder === 1) {
            result.valid = false;
            const data = `length: ${input.length}`;
            Base64.#addMessage(result.messages, Codes.DEC_INVALID_BASE64_LENGTH, null, data);
            return result;
        }

        if (remainder > 0) {
            result.paddingFixed = true;
            const data = `remainder: ${remainder}`;
            Base64.#addMessage(result.messages, Codes.PADDING_RESTORED, null, data);
            input += "=".repeat(4 - remainder);
        }

        result.normalizedText = input;
        return result;
    }

    /**
     * Evaluates a standardized Base64 target string against dialect alphabets,
     * looking for internal alignment tokens and trailing boundaries before giving clearance.
     * * @private
     */
    static #validate(value) {

        const result = this.#normalize(value);

        if (!result.valid) {
            return result;
        }

        const text = result.normalizedText;

        // =====================================================
        // INTERNAL PADDING CHECK
        // =====================================================

        const internalPaddingRegex = /=[A-Za-z0-9+/]/;
        if (internalPaddingRegex.test(text)) {
            result.valid = false;
            Base64.#addMessage(result.messages, Codes.DEC_MALFORMED_PADDING_POSITION);
            return result;
        }

        // =====================================================
        // BASE64 ALPHABET CHECK
        // =====================================================

        const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;

        if (!base64Regex.test(text)) {
            result.valid = false;
            Base64.#addMessage(result.messages, Codes.DEC_INVALID_BASE64_CHARACTERS);
            return result;
        }

        // =====================================================
        // PADDING VALIDATION
        // =====================================================

        const match = text.match(/(=*)$/);
        const padding = match ? match[1] : "";
        if (padding.length > 2) {
            result.valid = false;
            const data = `padding length: ${padding.length}`;
            Base64.#addMessage(result.messages, Codes.DEC_INVALID_BASE64_PADDING, null, data);
            return result;
        }

        Base64.#addMessage(result.messages, Codes.DEC_BASE64_VALIDATION_SUCCESS);
        return result;
    }

    /**
     * Main decoding engine optimized for premium web interfaces.
     * Executes end-to-end extraction, character telemetry, structural testing, and builds message profiles.
     * * @param {string} value - Raw user interface string payload.
     * @returns {Object} Analytical execution block matching rich system interfaces.
     */
    static decode(value) {

        const result = {
            valid: true,
            decodedText: "",
            bytes: null,
            type: null,
            isUtf8: null,
            characterCount: 0,
            byteCount: 0,
            paddingFixed: false,
            messages: []
        };

        const validation = Base64.#validate(value);
        result.type = validation.type;
        result.paddingFixed = validation.paddingFixed;
        result.messages.push(...validation.messages);

        if (!validation.valid) {
            result.valid = false;
            return result;
        }

        // =====================================================
        // DECODE
        // =====================================================

        let binary;
        try {
            binary = Base64.decodeRaw(validation.normalizedText);
        }
        catch {
            result.valid = false;
            Base64.#addMessage(result.messages, Codes.DEC_BASE64_DECODE_FAILED);
            return result;
        }

        result.byteCount = binary.length;
        Base64.#addMessage(result.messages, Codes.DEC_BASE64_DECODE_SUCCESS);

        // =====================================================
        // UTF-8 CHECK
        // =====================================================

        result.bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

        result.isUtf8 = Base64.isUtf8FromBinary(binary);
        if (result.isUtf8) {
            const utf8Text = new TextDecoder().decode(result.bytes);
            result.decodedText = utf8Text;
            result.characterCount = utf8Text.length;
            Base64.#addMessage(result.messages, Codes.DEC_UTF8_VALID);

            // check if there are only white spaces
            if (utf8Text.trim().length === 0 && utf8Text.length > 0) {
                const whitespaceData = `${utf8Text.length} spaces/tabs`;
                Base64.#addMessage(result.messages, Codes.DEC_ONLY_WHITESPACE_DETECTED, null, whitespaceData);
            }

        } else {
            result.decodedText = binary;
            Base64.#addMessage(result.messages, Codes.DEC_UTF8_INVALID);
        }

        const charData = `: ${result.characterCount}`;
        const byteData = `: ${result.byteCount}`;

        Base64.#addMessage(result.messages, Codes.DEC_CHARACTER_COUNT, charData);
        Base64.#addMessage(result.messages, Codes.DEC_BYTE_COUNT, byteData);
        
        return result;
    }

    /**
     * Inspects raw decoupled binary data streams to certify conformity with the UTF-8 schema.
     * * @param {string} binary - Raw decoupled sequence stream.
     * @returns {boolean} True if compliant with standard UTF-8 text envelopes.
     */
    static isUtf8FromBinary(binary) {
        try {
            const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
            new TextDecoder("utf-8", {fatal: true}).decode(bytes);
            return true;

        } catch {
            return false;
        }
    }

    /**
     * Encodes a standard string value into Base64 or URL-Safe Base64 format.
     * Implements encoding options like stripping padding and returns detailed telemetry.
     * * @param {string} input - The plain text to encode.
     * @param {Object} [options={}] - Encoding modifiers (base64Url, removePadding).
     * @returns {Object} Comprehensive analytics data block along with the final encoded content.
     */
    static encode(input, options = {}) {
        const result = {
            valid: true,
            encodedText: "",
            type: "base64",
            isUtf8: true,
            inputCharacterCount: 0,
            byteCount: 0,
            paddingRemoved: false,
            messages: []
        };

        const settings = {
            base64Url: false,
            removePadding: false,
            ...options
        };

        // =====================================================
        // INPUT VALIDATION
        // =====================================================

        if (typeof input !== "string") {
            result.valid = false;

            Base64.#addMessage(result.messages, Codes.INPUT_NOT_STRING);

            return result;
        }

        if (input.length === 0) {
            result.valid = false;

            Base64.#addMessage(result.messages, Codes.INPUT_EMPTY);

            return result;
        }

        // =====================================================
        // UTF-8 ENCODING
        // =====================================================

        let bytes;
        try {
            bytes = new TextEncoder().encode(input);

        } catch {
            result.valid = false;

            Base64.#addMessage(result.messages, Codes.ENC_UTF8_ENCODING_FAILED);

            return result;
        }

        Base64.#addMessage(
            result.messages,
            Codes.ENC_UTF8_ENCODED
        );

        result.inputCharacterCount = input.length;
        result.byteCount = bytes.length;

        // =====================================================
        // CONVERT BYTES -> BINARY STRING
        // =====================================================

        const binary = String.fromCharCode.apply(null, bytes);

        // =====================================================
        // BASE64 ENCODE
        // =====================================================

        let encoded;
        try {
            encoded = btoa(binary);

        } catch {
            result.valid = false;

            Base64.#addMessage(result.messages, Codes.ENC_BASE64_ENCODE_FAILED);

            return result;
        }

        Base64.#addMessage(result.messages, Codes.ENC_BASE64_ENCODE_SUCCESS);

        // =====================================================
        // BASE64URL CONVERSION
        // =====================================================

        if (settings.base64Url) {

            encoded = encoded
                .replace(/\+/g, "-")
                .replace(/\//g, "_");

            result.type = "base64url";

            Base64.#addMessage(result.messages, Codes.ENC_BASE64URL_CONVERTED);

        } else {
            Base64.#addMessage(result.messages, Codes.BASE64_DETECTED);
        }

        // =====================================================
        // REMOVE PADDING
        // =====================================================

        if (settings.removePadding) {
            const originalLength = encoded.length;

            encoded = encoded.replace(/=+$/, "");

            if (encoded.length !== originalLength) {
                result.paddingRemoved = true;

                Base64.#addMessage(result.messages, Codes.PADDING_REMOVED);
            }
        }

        // =====================================================
        // FINAL OUTPUT
        // =====================================================

        result.encodedText = encoded;

        const inputCharacterData = `: ${result.inputCharacterCount}`;
        Base64.#addMessage(result.messages, Codes.ENC_INPUT_CHARACTER_COUNT, inputCharacterData);

        const outputCharacterData = `: ${result.encodedText.length}`;
        Base64.#addMessage(result.messages, Codes.ENC_OUTPUT_CHARACTER_COUNT, outputCharacterData);

        const byteData = `: ${result.byteCount}`;
        Base64.#addMessage(result.messages, Codes.ENC_BYTE_COUNT, byteData);

        return result;
    }
}

