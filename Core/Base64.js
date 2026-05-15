export default class Base64 {

    /**
     * Standard Base64 Decode
     */
    static decode(value) {
        if (!value) return "";
        
        return atob(value);
    }

    /**
     * Base64URL specific Decode (JWT style)
     */
    static decodeUrl(value) {
        if (!value) return "";

        // Convert Base64URL to Standard Base64
        let base64 = value.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4 !== 0) {
            base64 += "=";
        }
        return this.decode(base64);
    }

    /**
     * Base64URL to Bytes
     */
    static urlToBytes(value) {
        const binary = this.decodeUrl(value);
        return Uint8Array.from(binary, c => c.charCodeAt(0));
    }

    
    /* Validates if a string is a valid Base64URL encoded string.
    * This regex allows alphanumeric characters, hyphens, underscores, 
    * and optional trailing padding (=).
    */
    static isBase64Url(value) {
        if (typeof value !== "string" || value.length === 0) {
            return false;
        }

        // Regular expression for Base64URL:
        // ^[A-Za-z0-9\-_]+  -> Start with one or more URL-safe chars
        // [=]{0,2}$         -> End with zero to two padding characters
        const base64UrlRegex = /^[A-Za-z0-9\-_]+[=]{0,2}$/;
        
        return base64UrlRegex.test(value);
    }
}

