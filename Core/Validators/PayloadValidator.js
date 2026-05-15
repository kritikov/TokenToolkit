import Consts from "../Consts.js";
import Message from "../Messages/Message.js";
import Severity from "../Messages/Severity.js";
import MessageCodes from "../Messages/MessageCodes.js";

export default class PayloadValidator{

    static validate(payloadText, header) {
        const messages = [];

        messages. push(...PayloadValidator.#validateStructure(payloadText));
        messages. push(...PayloadValidator.#validateClaims(payloadText));
        messages. push(...PayloadValidator.#validateTypes(payloadText));
        messages. push(...PayloadValidator.#validateTime(payloadText));
        messages. push(...PayloadValidator.#validateConsistency(payloadText));
        messages. push(...PayloadValidator.#validateSecurity(payloadText, header));
        messages. push(...PayloadValidator.#validateContext(payloadText, header));

        return messages;
    }
    
    static #validateStructure(payloadText) {

        const messages = [];

        if (!payloadText || typeof payloadText !== "object" || Array.isArray(payloadText)) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_INVALID_OBJECT}));
            return messages;
        }

        const keys = Object.keys(payloadText);

        if (keys.length === 0) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_EMPTY, severity: Severity.CRITICAL}));
        }

        if (keys.length > 50) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_TOO_LARGE}));
        }

        const unknownRatio = keys.length > 0
            ? keys.filter(k => !Consts.StandardClaims[k]).length / keys.length
            : 0;

        if (unknownRatio > 0.7) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_UNKNOWN_RATIO}));
        }

        return messages;
    }

    static #validateClaims(payloadText) {

        const messages = [];

        // missing standard claims
        for (const [key, def] of Object.entries(Consts.StandardClaims)) {

            if (payloadText[key] === undefined || payloadText[key] === null) {

                const lowerKey = key.toLowerCase();
                if (lowerKey === "sub")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_SUB}));
                else if (lowerKey === "iss")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_ISS}));
                else if (lowerKey === "aud")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_AUD}));
                else if (lowerKey === "exp")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_EXP}));
                else if (lowerKey === "iat")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_IAT}));
                else if (lowerKey === "nbf")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_NBF}));
                else if (lowerKey === "jti")
                    messages.push(new Message({code: MessageCodes.PAYLOAD_MISSING_JTI}));
            }
        }

        return messages;
    }

    static #validateTypes(payloadText) {
        const messages = [];

        const isNumber = (v) => typeof v === "number";

        if (payloadText.exp !== undefined && !isNumber(payloadText.exp)) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_INVALID_EXP_TYPE}));
        }

        if (payloadText.iat !== undefined && !isNumber(payloadText.iat)) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_INVALID_IAT_TYPE}));
        }

        if (payloadText.nbf !== undefined && !isNumber(payloadText.nbf)) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_INVALID_NBF_TYPE}));
        }

        if (payloadText.aud) {
            const valid =
                typeof payloadText.aud === "string" ||
                (Array.isArray(payloadText.aud) && payloadText.aud.length > 0 && payloadText.aud.every(a => typeof a === "string"));

            if (!valid) {
                messages.push(new Message({code: MessageCodes.PAYLOAD_INVALID_AUD_TYPE}));
            }
        }

        return messages;
    }

    static #validateTime(payloadText) {
        const messages = [];

        const now = Math.floor(Date.now() / 1000);
        const skew = 300;
        const isNum = (v) => typeof v === "number";

        if (isNum(payloadText.exp) && payloadText.exp < now) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_TOKEN_EXPIRED}));
        }

        if (isNum(payloadText.iat) && payloadText.iat > now + skew) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_IAT_IN_FUTURE}));
        }

        if (isNum(payloadText.iat) && payloadText.iat < now - (5 * 31536000)) { // 5 χρόνια
            messages.push(new Message({code: MessageCodes.PAYLOAD_TIME_TOO_FAR_IN_PAST}));
        }

        if (isNum(payloadText.nbf) && payloadText.nbf > now) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_TOKEN_NOT_ACTIVE}));
        }

        return messages;
    }

    static #validateConsistency(payloadText) {
        const messages = [];

        const isNum = (v) => typeof v === "number";

        if (isNum(payloadText.exp) && isNum(payloadText.iat) && payloadText.exp < payloadText.iat) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_EXP_BEFORE_IAT}));
        }

        if (isNum(payloadText.nbf) && isNum(payloadText.iat) && payloadText.nbf < payloadText.iat) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_NBF_BEFORE_IAT}));
        }

        if (isNum(payloadText.nbf) && isNum(payloadText.exp) && payloadText.nbf > payloadText.exp) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_NBF_AFTER_EXP}));
        }

        return messages;
    }

    static #validateSecurity(payloadText, header) {
        const messages = [];

        const algorithm = header?.display?.algorithm;
        const isUnsigned = algorithm?.key === "none";

        if (isUnsigned && payloadText.exp) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_UNSIGNED_WITH_EXP}));
        }

        if (algorithm?.family == "HMAC" && Array.isArray(payloadText.aud)) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_HMAC_ARRAY_AUD}));
        }

        const longLife = payloadText.exp && ((payloadText.exp - Math.floor(Date.now() / 1000)) / 86400);

        if (longLife > 3650) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_EXTREME_LIFETIME}));
        }

        // Έλεγχος για ευαίσθητα δεδομένα (Passwords/Secrets)
        const sensitiveKeys = ["password", "secret", "pass", "pwd", "apikey"];
        const keys = Object.keys(payloadText).map(k => k.toLowerCase());
        if (keys.some(k => sensitiveKeys.includes(k))) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_SENSITIVE_DATA_EXPOSURE}));
        }

        return messages;
    }

    static #validateContext(payloadText, header) {
        const messages = [];

        const alg = header?.display?.algorithm?.key;

        // future expansion zone
        if (alg === "none" && payloadText.sub) {
            messages.push(new Message({code: MessageCodes.PAYLOAD_UNSIGNED_IDENTITY}));
        }

        return messages;
    }

}