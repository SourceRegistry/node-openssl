import {openssl} from "../src";

async function main() {
    // Generate a 2048-bit RSA private key
    const key = await openssl`genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:2048`.one();
    console.log('Private Key:\n', key.data);
    console.log('SHA-256:', key.sha256);

    // Generate a self-signed certificate
    const cert = await openssl`req -x509 -new -key ${key} -subj "/CN=localhost" -days 365 -outform PEM`.one();
    console.log('Certificate:\n', cert.data);
    console.log('Is Certificate Chain?', cert.isChain);
}

main().catch(console.error);
