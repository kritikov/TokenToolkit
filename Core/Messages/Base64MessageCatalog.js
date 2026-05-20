import Base64MessageCodes from "./Base64MessageCodes.js";
import Severity from "./Severity.js";

export default class Base64MessageCatalog {

    static map = {

        // =========================================================
        // INPUT / GENERAL (SHARED)
        // =========================================================

        [Base64MessageCodes.INPUT_NOT_STRING]: {
            severity: Severity.CRITICAL,
            title: "Invalid input type",
            details: "The operation requires a valid string input. The provided value belongs to a non-string data type, preventing safe character normalization, encoding, or decoding operations. Ensure the payload is passed as a raw text string before processing.",
            category: "input"
        },

        [Base64MessageCodes.INPUT_EMPTY]: {
            severity: Severity.CRITICAL,
            title: "Empty input",
            details: "The provided text payload is empty. Base64 encoding and decoding operations require a non-empty character sequence in order to perform byte conversion, validation, or normalization steps.",
            category: "input"
        },

        [Base64MessageCodes.WHITESPACE_REMOVED]: {
            severity: Severity.INFO,
            title: "Whitespace normalized",
            details: "Detected and removed formatting whitespace characters such as spaces, tabs, or line breaks ('\\r\\n'). These characters commonly appear after copy-paste operations from terminals, editors, emails, or formatted documents and may interfere with strict Base64 processing rules.",
            category: "normalization"
        },


        // =========================================================
        // TYPE DETECTION (SHARED)
        // =========================================================

        [Base64MessageCodes.BASE64_DETECTED]: {
            severity: Severity.INFO,
            title: "Base64 detected",
            details: "The payload matches the standard Base64 alphabet defined by RFC 4648. The sequence contains standard alphanumeric characters together with optional '+' and '/' symbols commonly used in traditional Base64 transport systems.",
            category: "detection"
        },

        [Base64MessageCodes.BASE64URL_DETECTED]: {
            severity: Severity.INFO,
            title: "Base64URL detected",
            details: "The payload uses the URL-safe Base64URL variant which replaces '+' with '-' and '/' with '_'. This format is commonly used in JWT tokens, signed URLs, web APIs, and browser-safe transport layers.",
            category: "detection"
        },


        // =========================================================
        // NORMALIZATION (SHARED)
        // =========================================================

        [Base64MessageCodes.PADDING_RESTORED]: {
            severity: Severity.INFO,
            title: "Padding restored",
            details: "The input length was not aligned to the required 4-character Base64 block structure. Missing trailing padding characters ('=') were automatically restored to satisfy strict Base64 decoding requirements.",
            category: "normalization"
        },

        [Base64MessageCodes.PADDING_REMOVED]: {
            severity: Severity.INFO,
            title: "Padding removed",
            details: "Trailing Base64 padding markers ('=') were intentionally stripped from the generated payload according to specific configuration parameters. Padding removal optimizes data size and is a native requirement in compact modern transport structures such as JSON Web Tokens (JWT) and decentralized web identifiers.",
            category: "normalization"
        },


        // =========================================================
        // VALIDATION ERRORS (DECODING)
        // =========================================================

        [Base64MessageCodes.DEC_INVALID_BASE64_LENGTH]: {
            severity: Severity.CRITICAL,
            title: "Invalid Base64 length",
            details: "The Base64 payload length produces an impossible structural remainder during block validation. A valid Base64 stream must align into 4-character encoding groups. The detected layout indicates truncated, corrupted, or malformed encoded data.",
            category: "validation"
        },

        [Base64MessageCodes.DEC_INVALID_BASE64_CHARACTERS]: {
            severity: Severity.CRITICAL,
            title: "Invalid Base64 characters",
            details: "The payload contains characters outside the legal Base64/Base64URL alphabet ranges. Unsupported symbols, corrupted byte sequences, or malformed copy-paste operations may have damaged the encoded stream.",
            category: "validation"
        },

        [Base64MessageCodes.DEC_INVALID_BASE64_PADDING]: {
            severity: Severity.CRITICAL,
            title: "Invalid Base64 padding",
            details: "The Base64 payload contains an invalid padding layout. Valid Base64 data may only terminate with up to two '=' characters. Additional or malformed padding markers indicate structural corruption within the encoded stream.",
            category: "validation"
        },

        [Base64MessageCodes.DEC_MALFORMED_PADDING_POSITION]: {
            severity: Severity.CRITICAL,
            title: "Malformed padding position",
            details: "Padding markers ('=') were detected inside the main payload body instead of appearing strictly at the end of the Base64 sequence. This indicates corrupted structure, merged payloads, or invalid encoding output.",
            category: "validation"
        },


        // =========================================================
        // VALIDATION SUCCESS (DECODING)
        // =========================================================

        [Base64MessageCodes.DEC_BASE64_VALIDATION_SUCCESS]: {
            severity: Severity.SUCCESS,
            title: "Validation successful",
            details: "The Base64 payload passed all structural, alphabet, padding, and mathematical integrity checks required for safe decoding operations.",
            category: "validation"
        },


        // =========================================================
        // DECODING
        // =========================================================

        [Base64MessageCodes.DEC_BASE64_DECODE_SUCCESS]: {
            severity: Severity.SUCCESS,
            title: "Decode successful",
            details: "The Base64 payload was successfully translated back into its original binary representation without runtime decoding faults or structural inconsistencies.",
            category: "decoding"
        },

        [Base64MessageCodes.DEC_BASE64_DECODE_FAILED]: {
            severity: Severity.CRITICAL,
            title: "Decode failed",
            details: "The browser-native decoding engine rejected the payload during binary reconstruction. Although the payload may partially satisfy superficial validation rules, its internal structure failed strict runtime decoding requirements.",
            category: "decoding"
        },


        // =========================================================
        // UTF-8 (DECODING)
        // =========================================================

        [Base64MessageCodes.DEC_UTF8_VALID]: {
            severity: Severity.SUCCESS,
            title: "Valid UTF-8 text",
            details: "The decoded binary payload was successfully validated as proper UTF-8 encoded text. All byte sequences map correctly to readable textual characters and can safely be rendered as plain text, JSON, source code, or structured textual data.",
            category: "encoding"
        },

        [Base64MessageCodes.DEC_UTF8_INVALID]: {
            severity: Severity.WARNING,
            title: "Non UTF-8 content",
            details: "The payload decoded successfully into raw binary data, but the resulting byte sequences do not form valid UTF-8 text. This is expected for binary assets such as images, encrypted blobs, certificates, compiled files, or arbitrary binary streams.",
            category: "encoding"
        },

        [Base64MessageCodes.DEC_ONLY_WHITESPACE_DETECTED]: {
            severity: Severity.INFO,
            title: "Only whitespace characters detected",
            details: "The payload was successfully decoded, but its content consists exclusively of horizontal or vertical whitespace characters (such as spaces, tabs, or line breaks). While legally decoded, no printable alphanumeric characters are present in the final string.",
            category: "encoding"
        },


        // =========================================================
        // METRICS (DECODING)
        // =========================================================

        [Base64MessageCodes.DEC_CHARACTER_COUNT]: {
            severity: Severity.INFO,
            title: "Decoded character count",
            details: "Represents the total number of visible UTF-8 characters produced after decoding the Base64 payload into readable text.",
            category: "metrics"
        },

        [Base64MessageCodes.DEC_BYTE_COUNT]: {
            severity: Severity.INFO,
            title: "Decoded byte size",
            details: "Represents the total raw binary size of the decoded payload in bytes after Base64 conversion.",
            category: "metrics"
        },


        // =========================================================
        // ENCODING
        // =========================================================

        [Base64MessageCodes.ENC_BASE64_ENCODE_SUCCESS]: {
            severity: Severity.SUCCESS,
            title: "Encoding successful",
            details: "The input text was successfully converted into a valid Base64 representation without runtime conversion failures or byte corruption.",
            category: "encoding"
        },

        [Base64MessageCodes.ENC_BASE64_ENCODE_FAILED]: {
            severity: Severity.CRITICAL,
            title: "Encoding failed",
            details: "The browser-native encoding pipeline failed while attempting to convert the provided text into Base64 format. This may indicate malformed internal character sequences or unexpected runtime conversion errors.",
            category: "encoding"
        },

        [Base64MessageCodes.ENC_BASE64URL_CONVERTED]: {
            severity: Severity.INFO,
            title: "Converted to Base64URL",
            details: "The generated Base64 payload was successfully transformed into the URL-safe Base64URL variant by replacing '+' with '-' and '/' with '_'. This modification eliminates the need for percentage-encoding (%XX) when distributing the token or payload via web HTTP headers, query strings, or URI paths.",
            category: "normalization"
        },

        [Base64MessageCodes.ENC_UTF8_ENCODED]: {
            severity: Severity.SUCCESS,
            title: "UTF-8 conversion successful",
            details: "The input text was successfully converted into a UTF-8 byte stream prior to Base64 encoding.",
            category: "encoding"
        },

        [Base64MessageCodes.ENC_UTF8_ENCODING_FAILED]: {
            severity: Severity.CRITICAL,
            title: "UTF-8 encoding failed",
            details: "The input text could not be converted into a valid UTF-8 byte stream before Base64 encoding.",
            category: "encoding"
        },

        [Base64MessageCodes.ENC_INPUT_CHARACTER_COUNT]: {
            severity: Severity.INFO,
            title: "Input character count",
            details: "Represents the total number of characters processed before Base64 encoding.",
            category: "metrics"
        },

        [Base64MessageCodes.ENC_BYTE_COUNT]: {
            severity: Severity.INFO,
            title: "Encoded byte size", // Επιστροφή στον αρχικό σου τίτλο
            details: "Represents the absolute binary footprint of the generated Base64/Base64URL output payload in bytes. Since the output alphabet consists entirely of standard ASCII characters, this metric directly scales with the final character length.",
            category: "metrics"
        },

        [Base64MessageCodes.ENC_OUTPUT_CHARACTER_COUNT]: {
            severity: Severity.INFO,
            title: "Encoded output length",
            details: "Represents the total number of characters contained in the generated Base64 output string.",
            category: "metrics"
        }
    }
}