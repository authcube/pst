import express from 'express';
import { PSTIssuer, keyGen } from "../src/index.js";

// Só funciona se colocar no arquivo ./lib/example/index.js
//
// import crypto, { getRandomValues } from 'crypto' // should have webcrypto.getRandomValues defined
// if (typeof globalThis.crypto !== 'object') {
//     globalThis.crypto = crypto
// }
// if (typeof global.crypto.getRandomValues !== 'function') {
//   global.crypto.getRandomValues = getRandomValues
// }
import crypto from "crypto";
globalThis.crypto = crypto as Crypto;

const app = express();
const port = process.env.PORT || 3000;
const expiryEnv = process.env.EXPIRY;
const privateKeyEnv = process.env.PRIVATE_KEY;
const publicKeyEnv = process.env.PUBLIC_KEY;
let globalIssuer: PSTIssuer | null = null;

function initializeIssuer(): Promise<PSTIssuer> {
    return new Promise(async (resolve) => {
        let keys: { privateKey?: Uint8Array; publicKey?: Uint8Array } = {};
        if (privateKeyEnv && publicKeyEnv) {
            let privateKey = await Uint8Array.from(Buffer.from(privateKeyEnv, 'base64'));
            let publicKey = await Uint8Array.from(Buffer.from(publicKeyEnv, 'base64'));
            keys = { privateKey, publicKey };
        } else {
            keys = await keyGen();
        }
        let expiry: number;
        if (expiryEnv) {
            expiry = parseInt(expiryEnv, 10);
        } else {
            const now = new Date();
            const timedelta = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
            expiry = timedelta.getTime();
        }
        const issuer = new PSTIssuer(keys.publicKey!, expiry);
        resolve(issuer);
    });
}


async function getIssuer() {
    if (!globalIssuer) {
        globalIssuer = await initializeIssuer();
    }
    return globalIssuer;
}

app.get('/.well-known/trust-token/key-commitment', async (_, res) => {
    let issuer = await getIssuer();
    res.set({
        "Content-Type": "application/pst-issuer-directory"
    });
    let key_commitment_data = await issuer.key_commitment_data();
    res.json(await key_commitment_data);
});


app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
