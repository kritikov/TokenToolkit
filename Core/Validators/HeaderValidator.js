import Consts from "../Consts.js";
import Message from "../Messages/Message.js";
import Severity from "../Messages/Severity.js";
import MessageCodes from "../Messages/MessageCodes.js";

export default class HeaderValidator{

    static validate(headerText) {
        // 1. Πρώτα ελέγχουμε τη δομή
        const structureMessages = HeaderValidator.#validateStructure(headerText);
        
        // Αν το αντικείμενο είναι άκυρο (π.χ. null ή string), σταματάμε αμέσως
        if (structureMessages.some(m => m.code === MessageCodes.HEADER_INVALID_OBJECT)) {
            return structureMessages;
        }

        const messages = [...structureMessages];
        messages. push(...HeaderValidator.#validateConflicts(headerText));
        messages. push(...HeaderValidator.#validateSecurity(headerText));
        messages. push(...HeaderValidator.#validateUrls(headerText));
        messages. push(...HeaderValidator.#validateCrit(headerText));
        return messages;
    }

    static #validateSecurity(headerText) {
        const messages = [];
        const alg = headerText.alg;

        // Missing alg
        if (!alg) {
            messages.push(new Message({code: MessageCodes.HEADER_MISSING_ALG}));
            return messages; 
        }

        const algInfo = Consts.AlgorithmInfo[alg];
        
        // Unknown algorithm 
        if (!algInfo) {
            messages.push(new Message({code: MessageCodes.HEADER_UNKNOWN_ALGORITHM, data: alg }));
            return messages;
        }

        // alg = none
        if (algInfo?.securityLevel === "unsafe" || alg === "none") {
            messages.push(new Message({code: MessageCodes.HEADER_ALG_NONE}));
            return messages;
        }

        // asymmetric alg without key metadata
        if (algInfo?.type === "asymmetric") {
            const hasKeyInfo =
                headerText.kid ||
                headerText.jku ||
                headerText.x5u ||
                headerText.x5c ||
                headerText.jwk;

            if (!hasKeyInfo) {
                messages.push(new Message({code: MessageCodes.HEADER_ASYMMETRIC_NO_KEY_REFERENCE}));
            }
        }

        // Symmetric alg with asymmetric metadata (Algorithm Confusion Risk)
        if (algInfo?.type === "symmetric") {
            const hasAsymmetricMetadata = 
                headerText.jku || 
                headerText.x5u || 
                headerText.x5c || 
                headerText.jwk;

            if (hasAsymmetricMetadata) {
                messages.push(new Message({code: MessageCodes.HEADER_SYMMETRIC_ALGO_EXPECTED_ASYMMETRIC}));
            }
        }

        // JWE/JWS Confusion
        // Αν το algInfo.type υπάρχει, σημαίνει ότι είναι JWS (Signed). 
        // Αν υπάρχει ταυτόχρονα το 'enc', τότε έχουμε confusion με JWE.
        if (headerText.enc && algInfo && (algInfo.type === "symmetric" || algInfo.type === "asymmetric")) {
            messages.push(new Message({code: MessageCodes.HEADER_JWE_JWS_CONFUSION}));
        }

        // EdDSA misuse
        if (algInfo?.family === "EdDSA") {
            // Το EdDSA είναι πιο σύγχρονο και συνήθως δεν χρησιμοποιεί jku/x5c
            if (headerText.x5c || headerText.jku|| headerText.x5u) {
                messages.push(new Message({code: MessageCodes.HEADER_EDDSA_UNUSUAL_KEY_RESOLUTION}));
            }
        }

        return messages;
    }

    static #validateConflicts(headerText) {
        const messages = [];

        const hasJku = !!headerText.jku;
        const hasJwk = !!headerText.jwk;
        const hasX5c = !!headerText.x5c;
        const hasKid = !!headerText.kid;
        const hasX5u = !!headerText.x5u;

        // 1. jku + jwk
        if (hasJku && hasJwk) {
            messages.push(new Message({code: MessageCodes.HEADER_CONFLICTING_JKU_JWK}));
        }

        // 2. x5c + jwk
        if (hasX5c && hasJwk) {
            messages.push(new Message({code: MessageCodes.HEADER_CONFLICTING_X5C_JWK}));
        }

        // 3. ambiguity without kid (merged logic)
        if ((hasJku || hasX5c || hasX5u) && !hasKid) {
            messages.push(new Message({code: MessageCodes.HEADER_KEY_RESOLUTION_AMBIGUITY}));
        }

        // 4. cty misuse
        if (headerText.cty && headerText.cty !== "JWT") {
            messages.push(new Message({code: MessageCodes.HEADER_NON_STANDARD_CTY}));
        }

        return messages;
    }

    static #validateCrit(headerText) {
        const messages = [];

        const crit = headerText.crit;

        if (!crit) return messages;

        if (!Array.isArray(crit)) {
            messages.push(new Message({code: MessageCodes.HEADER_CRIT_NOT_ARRAY}));
            return messages;
        }

        if (crit.length === 0) {
            messages.push(new Message({code: MessageCodes.HEADER_CRIT_EMPTY}));
            return messages;
        }

        for (const item of crit) {
            if (typeof item !== "string") {
                messages.push(new Message({code: MessageCodes.HEADER_CRIT_NON_STRING}));
                return messages;
            }
        }

        const unknown = crit.filter(k => !(k in headerText));
        if (unknown.length > 0) {
            messages.push(new Message({code: MessageCodes.HEADER_CRIT_UNKNOWN_FIELDS, data: unknown.join(", ")}));
        }

        // Non-standard fields check
        const standardKeys = Object.keys(Consts.StandardHeaders);
        const nonStandard = crit.filter(k => !standardKeys.includes(k));
        if (nonStandard.length > 0) {
            messages.push(new Message({code: MessageCodes.HEADER_CRIT_NON_STANDARD_FIELDS, data: nonStandard.join(", ")}));
        }

        return messages;
    }

    static #validateUrls(headerText) {
        const messages = [];
        const urlFields = ["jku", "x5u"];
        const urlCodes = {
            "invalid-url": MessageCodes.HEADER_INVALID_URL,
            "non-https": MessageCodes.HEADER_NON_HTTPS_URL,
            "unsafe-host": MessageCodes.HEADER_UNSAFE_HOST_URL
        };

        const checkUrl = (url) => {
            try {
                const u = new URL(url);

                if (u.protocol !== "https:") {
                    return "non-https";
                }

                if (u.hostname === "localhost" || /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) {
                    return "unsafe-host";
                }

                return null;
            } catch {
                return "invalid-url";
            }
        };

        for (const field of urlFields) {

            const value = headerText[field];
            if (!value) continue;

            const issue = checkUrl(value);

            if (issue) {
                messages.push(new Message({code: urlCodes[issue], data: `field: ${field}`}));
            }
        }

        return messages;
    }

    static #validateStructure(headerText) {
        const messages = [];

        if (!headerText || typeof headerText !== "object" || Array.isArray(headerText)) {
            messages.push(new Message({code: MessageCodes.HEADER_INVALID_OBJECT}));
            return messages;
        }

        const keys = Object.keys(headerText);

        if (keys.length === 0) {
            messages.push(new Message({code: MessageCodes.HEADER_EMPTY}));
        }

        if (keys.length > 25) {
            messages.push(new Message({code: MessageCodes.HEADER_TOO_LARGE}));
        }

        const standardKeys = Object.keys(Consts.StandardHeaders);
        const unknown = keys.filter(k => !standardKeys.includes(k));
        const ratio = unknown.length / keys.length;
        if (ratio > 0.6) {
            messages.push(new Message({code: MessageCodes.HEADER_UNKNOWN_RATIO}));
        }

        // Typ check
        if (headerText.typ && headerText.typ !== "JWT") {
            messages.push(new Message({code: MessageCodes.HEADER_UNEXPECTED_TYP, context: headerText.typ}));
        }

        return messages;
    }
}