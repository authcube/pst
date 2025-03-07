
import express from 'express';
import {PSTRedeemer, PSTResources} from "../src/index.js";

const app = express();
const port = process.env.PORT || 3000;
const BASE64FORMAT = /^[a-zA-Z0-9+/=]+$/;

app.use(express.static("example/public"));
app.set("view engine", "ejs");
app.set("views", "example/views");

app.get('/.well-known/trust-token/key-commitment', async (_, res) => {
    let issuer = await PSTResources.getIssuer();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    let key_commitment_data = await issuer.key_commitment_data();
    res.write(JSON.stringify(key_commitment_data));
    res.end();
});

app.get(`/private-state-token/issuance`, async (req, res) => {

    console.debug(req.headers);
    const sec_private_state_token = req.headers["sec-private-state-token"] as string;
    console.debug({sec_private_state_token});

    if (sec_private_state_token && !sec_private_state_token.match(BASE64FORMAT)) {
        return res.sendStatus(400);
    }

    try {

        let issuer = await PSTResources.getIssuer();
        const token = await issuer.issueToken(sec_private_state_token);

        res.statusCode = 200
        res.setHeader('Content-Type', "text/html")
        res.append("sec-private-state-token", token);
        res.setHeader('Sec-Private-State-Token', token)
        res.write("Issuing tokens.")
        res.send();

        return res.end();

    } catch (e: any) {
        console.error("Error issuing PST", e);
        return res.sendStatus(500);
    }
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
            const redeemer = new PSTRedeemer();

            const resToken = await redeemer.redeemToken(redemptionToken);

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
