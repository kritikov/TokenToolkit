export default class MessageCodes {

    // =========================================================
    // HEADER - STRUCTURE
    // =========================================================

    static HEADER_INVALID_OBJECT = "HEADER_INVALID_OBJECT";
    static HEADER_EMPTY = "HEADER_EMPTY";
    static HEADER_TOO_LARGE = "HEADER_TOO_LARGE";
    static HEADER_UNKNOWN_RATIO = "HEADER_UNKNOWN_RATIO";

    // =========================================================
    // HEADER - SECURITY
    // =========================================================

    static HEADER_ALG_NONE = "HEADER_ALG_NONE";
    static HEADER_ASYMMETRIC_NO_KEY_REFERENCE = "HEADER_ASYMMETRIC_NO_KEY_REFERENCE";
    static HEADER_JWE_JWS_CONFUSION = "HEADER_JWE_JWS_CONFUSION";
    static HEADER_EDDSA_UNUSUAL_KEY_RESOLUTION = "HEADER_EDDSA_UNUSUAL_KEY_RESOLUTION";
    static HEADER_SYMMETRIC_ALGO_EXPECTED_ASYMMETRIC = "HEADER_SYMMETRIC_ALGO_EXPECTED_ASYMMETRIC";

    // =========================================================
    // HEADER - CONFLICTS
    // =========================================================

    static HEADER_CONFLICTING_JKU_JWK = "HEADER_CONFLICTING_JKU_JWK";
    static HEADER_CONFLICTING_X5C_JWK = "HEADER_CONFLICTING_X5C_JWK";
    static HEADER_KEY_RESOLUTION_AMBIGUITY = "HEADER_KEY_RESOLUTION_AMBIGUITY";
    static HEADER_NON_STANDARD_CTY = "HEADER_NON_STANDARD_CTY";

    // =========================================================
    // HEADER - CRIT
    // =========================================================

    static HEADER_CRIT_NOT_ARRAY = "HEADER_CRIT_NOT_ARRAY";
    static HEADER_CRIT_EMPTY = "HEADER_CRIT_EMPTY";
    static HEADER_CRIT_NON_STRING = "HEADER_CRIT_NON_STRING";
    static HEADER_CRIT_UNKNOWN_FIELDS = "HEADER_CRIT_UNKNOWN_FIELDS";
    static HEADER_CRIT_NON_STANDARD_FIELDS = "HEADER_CRIT_NON_STANDARD_FIELDS";

    // =========================================================
    // HEADER - URLS
    // =========================================================

    static HEADER_INVALID_URL = "HEADER_INVALID_URL";
    static HEADER_NON_HTTPS_URL = "HEADER_NON_HTTPS_URL";
    static HEADER_UNSAFE_HOST_URL = "HEADER_UNSAFE_HOST_URL";

    // =========================================================
    // PAYLOAD - STRUCTURE
    // =========================================================

    static PAYLOAD_INVALID_OBJECT = "PAYLOAD_INVALID_OBJECT";
    static PAYLOAD_EMPTY = "PAYLOAD_EMPTY";
    static PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE";
    static PAYLOAD_UNKNOWN_RATIO = "PAYLOAD_UNKNOWN_RATIO";

    // =========================================================
    // PAYLOAD - CLAIMS
    // =========================================================

    static PAYLOAD_MISSING_SUB = "PAYLOAD_MISSING_SUB";
    static PAYLOAD_MISSING_ISS = "PAYLOAD_MISSING_ISS";
    static PAYLOAD_MISSING_AUD = "PAYLOAD_MISSING_AUD";
    static PAYLOAD_MISSING_EXP = "PAYLOAD_MISSING_EXP";
    static PAYLOAD_MISSING_IAT = "PAYLOAD_MISSING_IAT";
    static PAYLOAD_MISSING_NBF = "PAYLOAD_MISSING_NBF";
    static PAYLOAD_MISSING_JTI = "PAYLOAD_MISSING_JTI";

    // =========================================================
    // PAYLOAD - TYPES
    // =========================================================

    static PAYLOAD_INVALID_EXP_TYPE = "PAYLOAD_INVALID_EXP_TYPE";
    static PAYLOAD_INVALID_IAT_TYPE = "PAYLOAD_INVALID_IAT_TYPE";
    static PAYLOAD_INVALID_NBF_TYPE = "PAYLOAD_INVALID_NBF_TYPE";
    static PAYLOAD_INVALID_AUD_TYPE = "PAYLOAD_INVALID_AUD_TYPE";

    // =========================================================
    // PAYLOAD - TIME
    // =========================================================

    static PAYLOAD_TOKEN_EXPIRED = "PAYLOAD_TOKEN_EXPIRED";
    static PAYLOAD_IAT_IN_FUTURE = "PAYLOAD_IAT_IN_FUTURE";
    static PAYLOAD_TOKEN_NOT_ACTIVE = "PAYLOAD_TOKEN_NOT_ACTIVE";
    static PAYLOAD_TIME_TOO_FAR_IN_PAST = "PAYLOAD_TIME_TOO_FAR_IN_PAST";

    // =========================================================
    // PAYLOAD - CONSISTENCY
    // =========================================================

    static PAYLOAD_EXP_BEFORE_IAT = "PAYLOAD_EXP_BEFORE_IAT";
    static PAYLOAD_NBF_BEFORE_IAT = "PAYLOAD_NBF_BEFORE_IAT";
    static PAYLOAD_NBF_AFTER_EXP = "PAYLOAD_NBF_AFTER_EXP";

    // =========================================================
    // PAYLOAD - SECURITY
    // =========================================================

    static PAYLOAD_UNSIGNED_WITH_EXP = "PAYLOAD_UNSIGNED_WITH_EXP";
    static PAYLOAD_HMAC_ARRAY_AUD = "PAYLOAD_HMAC_ARRAY_AUD";
    static PAYLOAD_EXTREME_LIFETIME = "PAYLOAD_EXTREME_LIFETIME";

    // =========================================================
    // PAYLOAD - CONTEXT
    // =========================================================

    static PAYLOAD_UNSIGNED_IDENTITY = "PAYLOAD_UNSIGNED_IDENTITY";
    static PAYLOAD_NON_STANDARD_SUB = "PAYLOAD_NON_STANDARD_SUB";
    static PAYLOAD_SENSITIVE_DATA_EXPOSURE = "PAYLOAD_SENSITIVE_DATA_EXPOSURE";

    // =========================================================
    // SIGNATURE - STRUCTURE
    // =========================================================

    static SIGNATURE_ALG_NONE_WITH_SIGNATURE = "SIGNATURE_ALG_NONE_WITH_SIGNATURE";
    static SIGNATURE_MISSING = "SIGNATURE_MISSING";
    static SIGNATURE_WHITESPACE_OUTER = "SIGNATURE_WHITESPACE_OUTER";
    static SIGNATURE_WHITESPACE_INTERNAL = "SIGNATURE_WHITESPACE_INTERNAL";
    static SIGNATURE_TOO_SHORT = "SIGNATURE_TOO_SHORT";
    static STRUCTURE_TRAILING_DOT = "STRUCTURE_TRAILING_DOT";

    // =========================================================
    // SIGNATURE - ENCODING
    // =========================================================

    static SIGNATURE_INVALID_BASE64URL = "SIGNATURE_INVALID_BASE64URL";
    static SIGNATURE_INVALID_CHARS = "SIGNATURE_INVALID_CHARS";
    static SIGNATURE_HAS_PADDING = "SIGNATURE_HAS_PADDING";
    static SIGNATURE_DECODE_FAILED = "SIGNATURE_DECODE_FAILED";

    // =========================================================
    // SIGNATURE - LENGTH
    // =========================================================

    static SIGNATURE_RSA_TOO_SMALL = "SIGNATURE_RSA_TOO_SMALL";
    static SIGNATURE_PSS_TOO_SMALL = "SIGNATURE_PSS_TOO_SMALL";

    // =========================================================
    // SIGNATURE - CONSISTENCY
    // =========================================================

    static SIGNATURE_UNEXPECTED_LENGTH = "SIGNATURE_UNEXPECTED_LENGTH";
    static SIGNATURE_TOO_LARGE = "SIGNATURE_TOO_LARGE";

    // =========================================================
    // SIGNATURE - SECURITY
    // =========================================================

    static SIGNATURE_LOW_ENTROPY = "SIGNATURE_LOW_ENTROPY";
    static SIGNATURE_HMAC_TOO_LARGE = "SIGNATURE_HMAC_TOO_LARGE";
    static SIGNATURE_REPEATING_CHARS = "SIGNATURE_REPEATING_CHARS";
    
}