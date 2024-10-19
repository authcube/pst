import express from 'express';
import { PSTIssuer, keyGenWithID, IssueRequest } from "../src/index.js";

const app = express();
const port = process.env.PORT || 3000;
const BASE64FORMAT = /^[a-zA-Z0-9+/=]+$/;
let globalIssuer: PSTIssuer | null = null;

app.use(express.static("example/public"));
app.set("view engine", "ejs");
app.set("views", "example/views");

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
    if (counter === 1 && (!privateKeyEnv || !publicKeyEnv)) {
        const { privateKey, publicKey } = await keyGenWithID(counter);
        return { privateKey, publicKey };
    } else if (privateKeyEnv && publicKeyEnv) {
        const privateKey = Uint8Array.from(Buffer.from(privateKeyEnv, 'base64'));
        const publicKey = Uint8Array.from(Buffer.from(publicKeyEnv, 'base64'));
        return { privateKey, publicKey };
    } else {
        throw new Error(`Invalid combination of counter and key variables for counter ${counter}`);
    }
}

async function initializeIssuer(): Promise<PSTIssuer> {

    const keys: Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; expiry: number }>[] = [];
    for (let i = 1; i <= 6; i++) {
        const privateKeyEnv = process.env[`PRIVATE_KEY${i}`];
        const publicKeyEnv = process.env[`PUBLIC_KEY${i}`];
        const expiryEnv = process.env[`EXPIRY${i}`];
        if ((privateKeyEnv && publicKeyEnv) || (i === 1 && (!privateKeyEnv || !publicKeyEnv))) {
            keys.push(
                getKeyByEnv(privateKeyEnv, publicKeyEnv, i).then((result) => ({
                    ...result,
                    expiry: getExpiryByEnv(expiryEnv),
                }))
            );
            console.log(`Loaded private key ${i} -> ${privateKeyEnv}`);
            console.log(`Loaded public key ${i} -> ${publicKeyEnv}`);
            console.log(`Loaded expiry key ${i} -> ${expiryEnv}`);
        }
    }
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
    // res.writeHead(200, { 'Content-Type': 'application/pst-issuer-directory' });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    let key_commitment_data = await issuer.key_commitment_data();
    res.write(JSON.stringify(await key_commitment_data));
    res.end();
});

app.get(`/private-state-token/issuance`, async (req, res) => {
    //try {
        let issuer = await getIssuer();
        console.log(req.headers);
        const sec_private_state_token = req.headers["sec-private-state-token"] as string;
        console.log({sec_private_state_token});

        if (sec_private_state_token && !sec_private_state_token.match(BASE64FORMAT)) {
            return res.sendStatus(400);
        }

        if (sec_private_state_token) {
            const decodedToken = Uint8Array.from(Buffer.from(sec_private_state_token, 'base64'));
            // const decodedToken = Uint8Array.from(atob(sec_private_state_token), c => c.charCodeAt(0));
            const tokReq = IssueRequest.deserialize(decodedToken);
            console.log(`token request: ${tokReq.serialize()}`);
            const tokRes = await issuer.issue(tokReq);
            const tokResSerialized = tokRes.serialize();
            const token = Buffer.from(tokResSerialized).toString('base64');

            const tokRes2 = await issuer.issue2(sec_private_state_token);
            // @ts-ignore
            const respB64 = btoa(String.fromCharCode.apply(null, tokRes2))

            // const respB64 = btoa(String.fromCharCode.apply(null, resp))
            console.log(`token serialized: (${tokResSerialized.length}) ${tokResSerialized}`);
            console.log(`token response KeyID: ${tokRes.keyID}`);
            console.log(`token response Issued: ${tokRes.issued}`);
            console.log(`token b64: (${token.length}) ${token}`);
            console.log(`token respB64: (${respB64.length}) ${respB64}`);

            res.statusCode = 200
            res.setHeader('Content-Type', "text/html")
            res.append("sec-private-state-token", token);
            // res.setHeader('Sec-Private-State-Token', respB64)
            res.setHeader('Sec-Private-State-Token', token)
            res.write("Issuing tokens.")
            // return res.send();
            res.send();

            return res.end();

        }
        return res.sendStatus(400);
    /*}
    catch (e){
        console.log(`Error on issuance: ${e}`)
        return res.sendStatus(500);
    }*/
});

app.get("/", async (_, res) => {
    return res.render("issuer")
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
