# TokenToolkit.js 🛠️

A lightweight, local-first JavaScript utility library designed for deep JWT parsing, metadata extraction, and static security inspection.

`TokenToolkit` is the core parsing engine powering the **nKode JWT Inspector**. It decodes tokens entirely in-memory, enriches claims with human-readable parameters, and aggregates potential structural issues without any external network dependency.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language: ES6 JavaScript](https://img.shields.io/badge/Language-ES6%20JavaScript-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

---

## Features ✨

- 🔒 **100% Local-First:** Performs all Base64URL parsing and JSON structural analysis inside the client runtime. Zero server leaks.
- 🩺 **Deep Section Analysis:** Automatically splits and maps claims into structured `standard` and `custom` arrays.
- 🕒 **Smart Time Formats:** Automatically intercepts Unix timestamps (`exp`, `iat`, `nbf`) and exposes clean, human-readable ISO/UTC strings (`formattedDate`).
- ⚠️ **Issue Aggregation:** Integrates modular validators to catch configuration mistakes or malformed parts, organizing anomalies by component.

---

## Architecture & Usage 🚀

The package relies on modern ES modules. Import `TokenToolkit` to target a token:

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

---

## API Reference 📖

```javascript
TokenToolkit.decodeJWT(jwt)
```

Static entry point. Validates the raw string layout (part1.part2.part3). 
Returns: { valid: false, error: string } OR { valid: true, jwt: JWTInstance }.

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

    📝 [Deep Dive Article: The Anatomy of JSON Web Tokens]([https://nkode.gr/EN/tools/jwt-decoder](https://nkode.gr/EN/articles/286/the-anatomy-of-json-web-tokens-jwt-what-they-are-and-how-they-work))


<img width="590" height="681" alt="image" src="https://github.com/user-attachments/assets/640a646f-8aad-4e25-83b3-122da3727710" />

---

<img width="580" height="698" alt="image" src="https://github.com/user-attachments/assets/1997281b-b449-4742-8009-6fc6319894f2" />

---

<img width="894" height="841" alt="image" src="https://github.com/user-attachments/assets/c84ee37c-1820-43cc-83fb-f8d19e69e4f1" />

---
    
## 📄 License

TokenToolkit.js is free software licensed under the GNU GPL v3.0 or later.
