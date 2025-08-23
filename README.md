# @sourceregistry/node-openssl

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release to NPM](https://github.com/SourceRegistry/node-openssl/actions/workflows/publish-npm.yml/badge.svg)](https://github.com/SourceRegistry/node-openssl/actions/workflows/publish-npm.yml)

A lightweight, promise-based TypeScript wrapper for executing **OpenSSL** CLI commands directly from Node.js, with rich
buffer enhancements and a fluent, proxy-powered API.

This library abstracts the `openssl` command-line tool into a clean, asynchronous interface, enabling seamless
integration of common cryptographic operations such as key generation, certificate signing, hashing, and PEM parsing.

## Installation

Install the package using npm:

```bash
npm install @sourceregistry/node-openssl
```

> **Note**: Ensure `openssl` is installed and available in your system's PATH.

## Usage

### Getting Started

The primary interface is the `openssl` tagged template function, which allows you to run any OpenSSL command using
natural syntax.

```typescript
import {openssl} from '@sourceregistry/node-openssl';

async function main() {
    // Generate a 2048-bit RSA private key
    const key = await openssl`genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:2048`.one();
    console.log('Private Key:\n', key.data);
    console.log('SHA-256:', key.sha256);

    // Generate a self-signed certificate
    const cert = await openssl`req -x509 -new -key <(echo "${key.data}") -subj "/CN=localhost" -days 365 -outform PEM`.one();
    console.log('Certificate:\n', cert.data);
    console.log('Is Certificate Chain?', cert.isChain);
}

main();
```

### Working with Output Buffers

All command outputs are enhanced `Buffer` objects with metadata and utilities:

```typescript
const output = await openssl`x509 -in cert.pem -noout -text`;

console.log(output.type);        // e.g., "CERTIFICATE"
console.log(output.mimeType);    // e.g., "application/x-pkcs7-crl"
console.log(output.sha1);        // Base64URL-encoded SHA-1
console.log(output.md5);         // Base64URL-encoded MD5
console.log(output.data);        // PEM body (without headers)

// Convert to Node.js crypto KeyObject
const publicKey = output.toObject(); // createPublicKey(output)
```

### Accessing OpenSSL Version

```typescript
console.log('OpenSSL Version:', openssl.version);
// { major: 3, minor: 0, patch: 2, release_date: '...'}
```

### File I/O and Temporary Workdir

You can pass `Buffer` objects directly — they’re automatically written to temp files:

```typescript
const csrBuffer = Buffer.from('...');
const signedCert = await openssl`x509 -req -CA ca.crt -CAkey ca.key -in <(echo "${csrBuffer}") -outform PEM`;
```

Files produced by OpenSSL (e.g., `.crt`, `.pem`) are automatically read and included in the output array.

## API Overview

### <code>openssl\`...`</code>(Tagged Template)

Execute any OpenSSL command. Returns a `Promise<OpenSSLBuffer[]>`.

```ts
const outputs = await openssl`dgst -sha256 file.txt`;
```

### `.one()`

Convenience method to get the first output buffer:

```ts
const cert = await openssl`req -newkey ...`.one();
```

### `OpenSSLBuffer`

Enhanced `Buffer` with:

- `.sha1`, `.sha256`, `.md5`: Hashes (base64url-encoded)
- `.data`: PEM body (header/footer stripped)
- `.type`: PEM type (`CERTIFICATE`, `PRIVATE KEY`, etc.)
- `.isChain`: `true` if multiple certs in PEM
- `.certificates`: Array of full certificate blocks (if chain)
- `.mimeType`: Inferred MIME type
- `.toObject()`: Convert to `crypto.KeyObject`

### Static Methods

- `OpenSSL.exec(args)`: Low-level execution with array args
- `OpenSSL.init()`: Initialize and detect OpenSSL version (is run automatically when importing the library)
- `OpenSSL.AnalysePEM(buffer)`: Parse PEM metadata
- `OpenSSL.TransformBuffer(buffer)`: Enhance a Buffer

## Development

### Prerequisites

- Node.js (v22+ older might work)
- OpenSSL (installed and in PATH)

### Scripts

- `npm run build`: Compile TypeScript to `dist/`
- `npm run test`: Run unit tests (if any)
- `npm run lint`: Lint code with ESLint

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

We aim to support all standard OpenSSL workflows with a clean, type-safe interface.

## License

This project is licensed under the **Apache-2.0 License**. See the [LICENSE](LICENSE) file for details.
