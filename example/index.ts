import express from 'express';
import { PSTIssuer, keyGenWithID } from "../src/index.js";

const app = express();
const port = process.env.PORT || 3000;
const expiryEnv1 = process.env.EXPIRY1;
const expiryEnv2 = process.env.EXPIRY2;
const privateKeyEnv1 = process.env.PRIVATE_KEY1;
const publicKeyEnv1 = process.env.PUBLIC_KEY1;
const privateKeyEnv2 = process.env.PRIVATE_KEY2;
const publicKeyEnv2 = process.env.PUBLIC_KEY2;
let globalIssuer: PSTIssuer | null = null;

function getExpiryByEnv(env: string | undefined): number {
    if (env) {
        return parseInt(env, 10);
    } else {
        const now = new Date();
        const timedelta = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
        return timedelta.getTime();
    }
}

async function getKeyByEnv(privateKeyEnv: string | undefined, publicKeyEnv: string | undefined, counter: number): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    if (privateKeyEnv && publicKeyEnv) {
        const privateKey = Uint8Array.from(Buffer.from(privateKeyEnv, 'base64'));
        const publicKey = Uint8Array.from(Buffer.from(publicKeyEnv, 'base64'));
        return { privateKey, publicKey };
    } else {
        const { privateKey, publicKey } = await keyGenWithID(counter);
        return { privateKey, publicKey };
    }
}

async function initializeIssuer(): Promise<PSTIssuer> {

    const keys: Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; expiry: number }>[] = [
        getKeyByEnv(privateKeyEnv1, publicKeyEnv1, 1).then((result) => ({
            ...result,
            expiry: getExpiryByEnv(expiryEnv1),
        })),
        getKeyByEnv(privateKeyEnv2, publicKeyEnv2, 2).then((result) => ({
            ...result,
            expiry: getExpiryByEnv(expiryEnv2),
        })),
    ];

    const resolvedKeys = await Promise.all(keys);
    return new PSTIssuer(resolvedKeys);
}

async function getIssuer() {
    if (!globalIssuer) {
        globalIssuer = await initializeIssuer();
    }
    return globalIssuer;
}

app.get('/.well-known/trust-token/key-commitment', async (_, res) => {
    let issuer = await getIssuer();
    res.writeHead(200, { 'Content-Type': 'application/pst-issuer-directory' });
    let key_commitment_data = await issuer.key_commitment_data();
    res.write(JSON.stringify(await key_commitment_data));
    res.end();
    //res.json(await key_commitment_data);
});


app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
