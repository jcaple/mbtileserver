// Prints a base64 encoded RSA Certificate that can be set as an env var
// for the server to read.
const key = "bladyblah";
const rsaKey = "-----BEGIN CERTIFICATE-----\n" +
    key +
    "\n-----END CERTIFICATE-----";
const encoder = new TextEncoder();
const encoded = encoder.encode(rsaKey);
const base64 = Buffer.from(encoded).toString('base64');

console.log("Base64: " + base64);