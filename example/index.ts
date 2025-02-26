
import express from 'express';
import {PSTIssuer, keyGenWithID, IssueRequest, RedeemerRequest, PSTRedeemer} from "../src";

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
        const timeDelta = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
        return timeDelta.getTime();
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
    res.writeHead(200, { 'Content-Type': 'application/json' });
    let key_commitment_data = await issuer.key_commitment_data();
    res.write(JSON.stringify(key_commitment_data));
    res.end();
});

app.get(`/private-state-token/issuance`, async (req, res) => {
    let issuer = await getIssuer();
    console.debug(req.headers);
    const sec_private_state_token = req.headers["sec-private-state-token"] as string;
    console.debug({sec_private_state_token});

    if (sec_private_state_token && !sec_private_state_token.match(BASE64FORMAT)) {
        return res.sendStatus(400);
    }

    if (sec_private_state_token) {
        const decodedToken = Uint8Array.from(Buffer.from(sec_private_state_token, 'base64'));
        const tokReq = IssueRequest.deserialize(decodedToken);
        const tokRes = await issuer.issue(tokReq);
        const tokResSerialized = tokRes.serialize();
        const token = Buffer.from(tokResSerialized).toString('base64');


        console.debug(`token serialized: (${tokResSerialized.length}) ${tokResSerialized}`);
        console.debug(`token response KeyID: ${tokRes.keyID}`);
        console.debug(`token response Issued: ${tokRes.issued}`);
        console.debug(`token b64: (${token.length}) ${token}`);

        res.statusCode = 200
        res.setHeader('Content-Type', "text/html")
        res.append("sec-private-state-token", token);
        res.setHeader('Sec-Private-State-Token', token)
        res.write("Issuing tokens.")
        res.send();

        return res.end();

    }
    return res.sendStatus(400);
});

app.get("/", async (_, res) => {
    return res.render("issuer")
});

// endpoint to receive requests to /redeemer
app.get("/redeem", async (_, res) => {
    return res.render("redeemer")
})

app.get(`/private-state-token/redemption`, async (req, res) => {
    try {
        console.debug(req.headers);
        const redemptionToken = req.headers["sec-private-state-token"] as string;
        console.debug(`redemptionToken size: ${redemptionToken.length}`);
        console.debug({redemptionToken});

        if (redemptionToken && !redemptionToken.match(BASE64FORMAT)) {
            return res.sendStatus(400);
        }

        if (redemptionToken) {
            const decodedToken = Uint8Array.from(Buffer.from(redemptionToken, 'base64'));
            console.debug(`decoded token: ${decodedToken}`);
            const tokReq = RedeemerRequest.deserialize(decodedToken);
            console.debug(`token deserialized`);

            let redeemer = new PSTRedeemer();
            let issuer = await getIssuer();
            let redeemRes = await redeemer.redeem(tokReq, issuer);

            const resToken = Buffer.from(redeemRes.serialize()).toString('base64');

            res.statusCode = 200;
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.append("sec-private-state-token", resToken);
            res.write("Token redeemed.");
            return res.send();
        }

        return res.sendStatus(400);
    } catch (e) {
        console.error(`Error on redemption: ${e}`);
        return res.sendStatus(500);
    }
});

app.get("/private-state-token/send-rr", async (req, res) => {

    console.debug(req.headers);
    const redemptionRecord = req.headers["sec-redemption-record"] as string;
    console.debug(`redemptionToken size: ${redemptionRecord.length}`);
    console.debug({redemptionToken: redemptionRecord});

    // Extract the redemption-record value
    const redemptionRecordMatch = redemptionRecord.match(/redemption-record="([^"]+)"/);

    if (!redemptionRecordMatch || !redemptionRecordMatch[1]) {
        console.debug("Redemption record header not found");
        res.sendStatus(400)
    }

    const redemptionRecordValue = redemptionRecordMatch?.[1];
    console.debug(redemptionRecordValue);

    const r = {
        "record": redemptionRecordValue,
        "domain": req.originalUrl,
    }

    res.statusCode = 200;
    res.set({ "Access-Control-Allow-Origin": "*" })
    res.send(r)
})

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
