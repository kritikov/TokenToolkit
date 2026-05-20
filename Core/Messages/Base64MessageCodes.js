export default class Base64MessageCodes {

    // =========================================================
    // INPUT / GENERAL (SHARED)
    // =========================================================

    static INPUT_NOT_STRING = "INPUT_NOT_STRING";
    static INPUT_EMPTY = "INPUT_EMPTY";
    static WHITESPACE_REMOVED = "WHITESPACE_REMOVED";


    // =========================================================
    // TYPE DETECTION (SHARED)
    // =========================================================

    static BASE64_DETECTED = "BASE64_DETECTED";
    static BASE64URL_DETECTED = "BASE64URL_DETECTED";


    // =========================================================
    // NORMALIZATION (SHARED)
    // =========================================================

    static PADDING_RESTORED = "PADDING_RESTORED";
    static PADDING_REMOVED = "PADDING_REMOVED";


    // =========================================================
    // VALIDATION (DECODING)
    // =========================================================

    static DEC_INVALID_BASE64_LENGTH = "DEC_INVALID_BASE64_LENGTH";
    static DEC_INVALID_BASE64_CHARACTERS = "DEC_INVALID_BASE64_CHARACTERS";
    static DEC_INVALID_BASE64_PADDING = "DEC_INVALID_BASE64_PADDING";
    static DEC_MALFORMED_PADDING_POSITION = "DEC_MALFORMED_PADDING_POSITION";
    static DEC_BASE64_VALIDATION_SUCCESS = "DEC_BASE64_VALIDATION_SUCCESS";
    static DEC_ONLY_WHITESPACE_DETECTED = "DEC_ONLY_WHITESPACE_DETECTED";


    // =========================================================
    // DECODING
    // =========================================================

    static DEC_BASE64_DECODE_SUCCESS = "DEC_BASE64_DECODE_SUCCESS";
    static DEC_BASE64_DECODE_FAILED = "DEC_BASE64_DECODE_FAILED";


    // =========================================================
    // UTF-8 (DECODING)
    // =========================================================

    static DEC_UTF8_VALID = "DEC_UTF8_VALID";
    static DEC_UTF8_INVALID = "DEC_UTF8_INVALID";


    // =========================================================
    // METRICS (DECODING)
    // =========================================================

    static DEC_CHARACTER_COUNT = "DEC_CHARACTER_COUNT";
    static DEC_BYTE_COUNT = "DEC_BYTE_COUNT";


    // =========================================================
    // ENCODING
    // =========================================================

    static ENC_BASE64_ENCODE_SUCCESS = "ENC_BASE64_ENCODE_SUCCESS";
    static ENC_BASE64_ENCODE_FAILED = "ENC_BASE64_ENCODE_FAILED";

    static ENC_BASE64URL_CONVERTED = "ENC_BASE64URL_CONVERTED";

    static ENC_UTF8_ENCODED = "ENC_UTF8_ENCODED";
    static ENC_UTF8_ENCODING_FAILED = "ENC_UTF8_ENCODING_FAILED";


    // =========================================================
    // METRICS (ENCODING)
    // =========================================================

    static ENC_INPUT_CHARACTER_COUNT = "ENC_INPUT_CHARACTER_COUNT";
    static ENC_BYTE_COUNT = "ENC_BYTE_COUNT";
    static ENC_OUTPUT_CHARACTER_COUNT = "ENC_OUTPUT_CHARACTER_COUNT";
}