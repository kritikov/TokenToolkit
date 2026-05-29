# TokenToolkit.js 🛠️

A lightweight, local-first JavaScript facade library designed for deep JWT parsing, structural metadata extraction, and robust Base64/Base64URL encoding and decoding.

`TokenToolkit` is the core processing engine powering the **nKode Developer Utilities**. It processes tokens and data streams entirely in-memory, enriches claims with human-readable parameters, and aggregates potential structural issues without any external network dependency.

[![Language: ES6 JavaScript](https://img.shields.io/badge/Language-ES6%20JavaScript-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

---

## Features ✨

- 🔒 **100% Local-First:** Performs all Base64URL parsing, binary validation, and JSON structural analysis inside the client runtime. Zero server leaks.
- 🎛️ **Unified Facade:** A single entry point for handling both JSON Web Tokens and general-purpose Base64/Base64URL manipulations.
- 🩺 **Deep JWT Section Analysis:** Automatically splits and maps claims into structured `standard` and `custom` arrays.
- 🕒 **Smart Time Formats:** Automatically intercepts Unix timestamps (`exp`, `iat`, `nbf`) and exposes clean, human-readable ISO/UTC strings (`formattedDate`).
- ⚠️ **Issue Aggregation:** Integrates modular validators to catch configuration mistakes, invalid encodings, or malformed parts, organizing anomalies by component.

---

## Architecture & Usage 🚀

The package relies on modern ES modules. Import `TokenToolkit` to target a token or data sequence:

### 1. Decoding a JWT
```javascript
import TokenToolkit from "./TokenToolkit.js";

const rawJwt = "xxxxx.yyyyy.zzzzz";
const result = TokenToolkit.decodeJWT(rawJwt);

if (!result.valid) {
    console.error("Malformed token format:", result.error);
} else {
    const jwtInstance = result.jwt; // Returns instantiated JWT object
    
    // Quick plain objects conversion
    console.log(jwtInstance.toJSON());
}
```

### 2. Inspecting Enriched Metadata & Diagnostics
```javascript
const { jwt } = TokenToolkit.decodeJWT(rawJwt);

// Inspect evaluated payload claims and formatted timestamps
jwt.payload.display.standard.forEach(claim => {
    console.log(`Claim: ${claim.key} -> Value: ${claim.value}`);
    if (claim.formattedDate) {
        console.log(`🕒 Readable Date: ${claim.formattedDate}`); // "2026-05-15 11:08:00 UTC"
    }
});

// Intercept structural or security anomalies flagged by validators
if (jwt.header.issues.length > 0) {
    jwt.header.issues.forEach(issue => {
        console.warn(`[${issue.severity}] Header Anomaly: ${issue.text}`);
    });
}
```

### 2. Inspecting Enriched Metadata & Diagnostics
```javascript
import TokenToolkit from "./TokenToolkit.js";

// Multi-dialect decoding (Handles whitespace, safe padding, and standard/url alphabets)
const telemetry = TokenToolkit.decodeBase64("ZXlKaGJHY2lPaUpJVXpJMk5pSXNJbVY0Y0NJNk5pSmRmUT09");
console.log(telemetry.decodedText); // Plain output text
console.log(telemetry.bytes);       // The raw bytes
console.log(telemetry.messages);    // Full diagnostic logs array

// Custom safe Encoding
const encoded = TokenToolkit.encodeToBase64("Hello nKode!", { base64Url: true, removePadding: true });
console.log(encoded.encodedText); // "SGVsbG8gbktvZGUh" (URL-safe, no padding)
```

---

## API Reference 📖

```javascript
TokenToolkit.decodeJWT(jwt)
```

Static entry point. Validates the raw string layout (part1.part2.part3). 
Returns: { valid: false, error: string } OR { valid: true, jwt: JWTInstance }.

```javascript
TokenToolkit.decodeBase64(input)
```

Static wrapper for the advanced Base64 engine. Analyzes, standardizes, and decodes any standard or URL-safe Base64 stream.
Returns: Comprehensive analytical UI-ready evaluation object containing bytes telemetry, UTF-8 state, and warnings.

```javascript
TokenToolkit.encodeToBase64(input, options)
```
Static wrapper for custom Base64 string generation.
Options: { base64Url: boolean, removePadding: boolean }
Returns: Detailed serialization schema reporting layout shifts, byte tallies, and target texts.

```javascript
TokenToolkit.encodeToBase64FromFile(file)
```
Static wrapper for custom Base64 string generation from a file.
Returns: A clean, structured telemetry and payload block in base65 encoding.

```javascript
jwtInstance.toJSON()
```

Extracts the immediate string values of the header, payload, and signature components.

```javascript
jwtInstance.toJSONString(pretty = true)
```

Converts the internal component data into an optionally formatted JSON string.

---

## Ecosystem Integration 🌐

This library provides the native engine driving:

    🛠️ [nKode Online JWT Decoder & Inspector](https://nkode.gr/EN/tools/jwt-decoder)
    🛠️ [nKode Online Base64 Decoder & Inspector](https://nkode.gr/EN/tools/base64-decoder)
    🛠️ [nKode Online Base64 Encoder](https://nkode.gr/EN/tools/base64-encoder)

    📝 [Deep Dive Article: The Anatomy of JSON Web Tokens]([https://nkode.gr/EN/tools/jwt-decoder](https://nkode.gr/EN/articles/286/the-anatomy-of-json-web-tokens-jwt-what-they-are-and-how-they-work))


<img width="590" height="681" alt="image" src="https://github.com/user-attachments/assets/640a646f-8aad-4e25-83b3-122da3727710" />

---

<img width="580" height="698" alt="image" src="https://github.com/user-attachments/assets/1997281b-b449-4742-8009-6fc6319894f2" />

---

<img width="894" height="841" alt="image" src="https://github.com/user-attachments/assets/c84ee37c-1820-43cc-83fb-f8d19e69e4f1" />

---
    
## 📄 License

TokenToolkit.js is free software licensed under the GNU GPL v3.0 or later.
