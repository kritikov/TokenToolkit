import Consts from "./Consts.js";
import Base64 from "./Base64.js";
import HeaderValidator from "./Validators/HeaderValidator.js";
import PayloadValidator from "./Validators/PayloadValidator.js";
import SignatureValidator from "./Validators/SignatureValidator.js";
import Message from "./Messages/Message.js";
import Severity from "./Messages/Severity.js";

export default class JWT {
    
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
    
    toJSON() {
        return {
            header: this.header?.value || null,
            payload: this.payload?.value || null,
            signature: this.signature?.raw || null
        };
    }

    toJSONString(pretty = true) {

        return JSON.stringify(
            this.toJSON(),
            null,
            pretty ? 2 : 0
        );
    }

    headerToJSON() {
        return JSON.stringify(
            this.header?.value || null,
            null,
            pretty ? 2 : 0
        );
    }

    payloadToJSON() {
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
     * DECODER (STRUCTURE ONLY)
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
     * decode the header or the payload
     */
	static #decodePart(value, sectionName = "payload") {

		if (!Base64.isBase64Url(value)) {
			return {
                valid:false,
                error:"Invalid base64url encoding"
            }
		}

		try {
			return {
				valid: true,
				text: JSON.parse(Base64.decodeUrl(value))
			};
		}
		catch {
			return {
                valid:false,
                error: `Invalid JSON ${sectionName}`
            }
		}
	}

    /**
     * decode the signature
     */
    static #decodeSignature(value) {

        if (!Base64.isBase64Url(value)) {
            return {
                valid: false,
                error: "Invalid base64url encoding"
            };
        }

        return {
            valid: true,
            text: value
        };
    }

	/**
     * Analyze the decoded header and create the header object
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
     * Analyze the decoded payload and create the payload object
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
     * Analyze the decoded signature and create the signature object
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

    // validate the input format
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
