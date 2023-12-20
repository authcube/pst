import express from 'express';
import { PSTIssuer, keyGen } from "../src/index.js";

const app = express();
const port = process.env.PORT || 3000;
const expiryEnv = process.env.EXPIRY;
const privateKeyEnv = process.env.PRIVATE_KEY;
const publicKeyEnv = process.env.PUBLIC_KEY;


async function getIssuer() {
    let keys: { privateKey?: Uint8Array; publicKey?: Uint8Array } = {};
    if (privateKeyEnv && publicKeyEnv) {
        // Private key is present in environment, parse it
        let privateKey = await Uint8Array.from(Buffer.from(privateKeyEnv, 'base64'));
        let publicKey = await Uint8Array.from(Buffer.from(publicKeyEnv, 'base64'));
        keys = { privateKey, publicKey };
    }
    else {
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
    return new PSTIssuer(keys.publicKey!, expiry); // Use non-null assertion for keys.publicKey
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
