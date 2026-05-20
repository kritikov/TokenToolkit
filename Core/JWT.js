import Consts from "./Consts.js";
import Base64 from "./Base64.js";
import HeaderValidator from "./Validators/HeaderValidator.js";
import PayloadValidator from "./Validators/PayloadValidator.js";
import SignatureValidator from "./Validators/SignatureValidator.js";
import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";

/**
 * Main JSON Web Token (JWT) analyzer and decoder class.
 * Manages the full lifecycle of token structural compilation, segment parsing, metadata enrichment, and validation processing.
 */
export default class JWT {
    
    /**
     * Initializes a new instance of the JWT parser.
     * Sanitizes input data streams and immediately orchestrates downstream block diagnostics if structural baselines clear.
     * @param {string} raw - The raw dot-separated JSON Web Token sequence.
     */
    constructor(raw) {
		const trimmedRaw = typeof raw === "string" ? raw.trim() : raw;
        this.raw = trimmedRaw;
        this.decoded = null;
		this.header = null;
		this.payload = null;
		this.signature = null;

        const validation = JWT.isValidInput(trimmedRaw);

        if (validation.valid){
            this.decoded = JWT.#decode(trimmedRaw);
			this.header = JWT.#analyzeHeader(this.decoded.header);
            this.payload = JWT.#analyzePayload(this.decoded.payload, this.header);
            this.signature = JWT.#analyzeSignature(this.decoded.signature, this.header);
		}
	}

    // ===== PUBLIC =====
    
    /**
     * Projects the internal operational values into a structured data object mapping.
     * @returns {Object} A sanitized data model mapping key segments or null components.
     */
    toJSON() {
        return {
            header: this.header?.value || null,
            payload: this.payload?.value || null,
            signature: this.signature?.raw || null
        };
    }

    /**
     * Converts the standard segments state map directly into an exported JSON string asset.
     * @param {boolean} [pretty=true] - Toggles structured multiline output alignment spacing.
     * @returns {string} Fully serialized token string schema representation.
     */
    toJSONString(pretty = true) {

        return JSON.stringify(
            this.toJSON(),
            null,
            pretty ? 2 : 0
        );
    }

    /**
     * Serializes the unpacked active header segment metadata properties into an isolated JSON string context.
     * @param {boolean} [pretty=true] - Toggles multiline output structural nesting indent configurations.
     * @returns {string} Serialized active header attribute map block.
     */
    headerToJSON(pretty = true) {
        return JSON.stringify(
            this.header?.value || null,
            null,
            pretty ? 2 : 0
        );
    }

    /**
     * Serializes the unpacked active payload statement metadata properties into an isolated JSON string context.
     * @param {boolean} [pretty=true] - Toggles multiline output structural nesting indent configurations.
     * @returns {string} Serialized active claims attribute map block.
     */
    payloadToJSON(pretty = true) {
        return JSON.stringify(
            this.payload?.value || null,
            null,
            pretty ? 2 : 0
        );
    }


    // ---------------------------
	// STATIC
	// ---------------------------

    /**
     * Performs top-level layout fragmentation.
     * Isolates standard token compound sectors along index dot boundaries before piping streams to individual block decoders.
     * @private
     */
	static #decode(input) {

		const parts = input.split(".");

		if (parts.length !== 3) {
			throw new Error("Invalid JWT format");
		}

		const [header, payload, signature] = parts;

		return {
            header: JWT.#decodePart(header, "header"),
            payload: JWT.#decodePart(payload, "payload"),
            signature: JWT.#decodeSignature(signature)
        };
	}
    
    /**
     * Decodes and unpacks an isolated Base64URL string sector block into clean object structures.
     * Safe-catches string encoding failures or JSON malformations silently.
     * @private
     */
    static #decodePart(value, sectionName = "payload") {
        try {
            // 1. Αποκωδικοποίηση σε UTF-8 string (αν αποτύχει το b64 ή το UTF-8, πάει στο catch)
            const decodedText = Base64.decodeToUtf8(value);

            // 2. Μετατροπή σε αντικείμενο JSON (αν αποτύχει, πάει στο catch)
            return {
                valid: true,
                text: JSON.parse(decodedText)
            };
        }
        catch {
            // Πιάνει και τα σφάλματα της Base64 και του JSON.parse
            return {
                valid: false,
                error: `Invalid ${sectionName} structure or encoding`
            };
        }
    }

    /**
     * Audits the raw trailing signature sequence structure block against baseline Base64 requirements.
     * Retains the raw encoding layout string on success without executing plain text parsing transforms.
     * @private
     */
    static #decodeSignature(value) {
        try {
            // Ελέγχουμε μόνο αν είναι έγκυρο Base64 δομικά (δεν μας νοιάζει το UTF-8 ή το JSON)
            Base64.decodeRaw(value);

            return {
                valid: true,
                text: value // Επιστρέφουμε το raw string της υπογραφής
            };
        }
        catch {
            return {
                valid: false,
                error: "Invalid Base64URL signature encoding"
            };
        }
    }

	/**
     * Evaluates header element definitions against dictionary registries.
     * Maps cryptographic parameter scopes, separates custom components, and aggregates external structural validation reports.
     * @private
     */
	static #analyzeHeader(decodedHeader) {

        const result = {
            valid: decodedHeader.valid,
            value: null,
            raw: null,
            display: {
                standard: [],
                custom: []
            },
            issues: []
        };

        if (!decodedHeader.valid) {
            result.issues.push(new Message({text: decodedHeader.error || "Invalid header", severity: Severity.CRITICAL}));
            return result;
        }

        const headerText = decodedHeader.text;
        const alg = headerText.alg;

        result.value = headerText;
        result.raw = JSON.stringify(headerText, null, 2);

        const standardHeaders = [];
        const customHeaders = [];
       
        for (const [key, value] of Object.entries(headerText)) {

            const standardInfo = Consts.StandardHeaders[key];

            const item = {
                key,
                value,
                type: Array.isArray(value)
                    ? "array"
                    : value === null
                        ? "null"
                        : typeof value,
                raw: value,
                description: standardInfo?.description || null,
                category: standardInfo?.category || "custom",
                required: standardInfo?.required || false,
                critical: standardInfo?.critical || false,
                examples: standardInfo?.examples || [],
                standard: !!standardInfo
            };

            // enrich alg specifically
            if (key === "alg") {
                item.algorithmInfo = Consts.AlgorithmInfo[value] || null;
                if (item.algorithmInfo){
                    item.family = item.algorithmInfo.family;
                    item.hash = item.algorithmInfo.hash;
                    item.algorithmType = item.algorithmInfo.type;
                }
                item.supported = !!item.algorithmInfo;
                item.securityLevel = item.algorithmInfo?.securityLevel || "unknown";
            }

            if (standardInfo) {
                standardHeaders.push(item);
            }
            else {
                customHeaders.push(item);
            }
        }

        const algorithm = standardHeaders.find(x => x.key === "alg") || null;
        result.display.algorithm = algorithm;
        result.display.standard = standardHeaders;
        result.display.custom = customHeaders;

        const issues = HeaderValidator.validate(headerText);
        result.issues.push(...issues);

        return result;
    }

    /**
     * Dissects, filters, and standardizes decoded claims parameters.
     * Normalizes chronological numerical values into human-readable timestamp descriptions and runs target payload assertions.
     * @private
     */
    static #analyzePayload(decodedPayload, header) {

        const result = {
            valid: decodedPayload.valid,
            value: null,
            raw: null,
            display: {
                standard: [],
                custom: []
            },
            issues: []
        };

        if (!decodedPayload.valid) {
            result.issues.push(new Message({text: "Invalid payload encoding", severity: Severity.CRITICAL}));
            return result;
        }

        const payloadText = decodedPayload.text;
        const timeClaims = ["exp", "iat", "nbf"];

        result.value = payloadText;
        result.raw = JSON.stringify(payloadText, null, 2);

        for (const [key, value] of Object.entries(payloadText)) {
            const standardInfo = Consts.StandardClaims[key];

            const item = {
                key,
                value,
                raw: value,
                description: standardInfo?.info || null,
                type: standardInfo?.type || null,
                category: standardInfo?.category || "custom",
                required: standardInfo?.required || false,
                critical: standardInfo?.critical || false,
                standard: !!standardInfo
            };

            // if the claim is date time then display a formatted value of it
            if (timeClaims.includes(key) && typeof value === "number") {
                try {
                    // JWT timestamps are in seconds, while JavaScript expects milliseconds.
                    const date = new Date(value * 1000);
                    
                    //Check if the date is valid (e.g. if the number was huge/invalid).
                    if (!isNaN(date.getTime())) {
                        item.formattedDate = date.toISOString().replace("T", " ").substring(0, 19) + " UTC";
                    }
                } catch {
                    item.formattedDate = "Invalid Timestamp";
                }
            }

            if (standardInfo) {
                result.display.standard.push(item);
            }
            else {
                result.display.custom.push(item);
            }
        }

        const issues = PayloadValidator.validate(payloadText, header);
        result.issues.push(...issues);

        return result;
    }
    
    /**
     * Measures signature metrics and structures preview slices.
     * Delegates downstream cryptographic profile logic validations against current header metadata definitions.
     * @private
     */
	static #analyzeSignature(decodedSignature, header) {

        const result = {
            valid: decodedSignature.valid,
            value: null,
            raw: null,
            display: null,
            issues: []
        };

        if (!decodedSignature.valid) {
            result.issues.push(new Message({text: "Invalid signature encoding", severity: Severity.CRITICAL}));
            return result;
        }

        const signatureText = decodedSignature?.text || "";

        result.value = signatureText;
        result.raw = signatureText;

        result.display = {
            length: signatureText.length,
            preview: signatureText.length
                ? signatureText.slice(0, 12) + "..."
                : "(empty)"
        };

        const issues = SignatureValidator.validate(signatureText, header);
        result.issues.push(...issues);
       
        return result;
    }

    /**
     * Conducts quick preliminary string structural inspections.
     * Assures inputs are populated, string-based, and accurately split into exactly three logical segments.
     * @param {*} input - The unchecked data variable input map.
     * @returns {Object} Simple status mapping showing validation outcome flags and error reasons.
     */
    static isValidInput(input) {

		if (input == null) {
			return { valid: false, error: "JWT is required" };
		}

		if (typeof input !== "string") {
			return { valid: false, error: "JWT must be a string" };
		}

		const token = input.trim();

		if (!token) {
			return { valid: false, error: "JWT is empty" };
		}

		const parts = token.split(".");

		if (parts.length !== 3) {
			return { valid: false, error: "Invalid JWT format" };
		}

        return { valid: true, error: "" };
	}
  
}
