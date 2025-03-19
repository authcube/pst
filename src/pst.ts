// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Original copy: https://github.com/cloudflare/privacypass-ts/blob/main/src/priv_verif_token.ts
// the original copy has been modified in order to implement Private State Tokens API
// Same copyrights banner from the original copy has been preserved as Apache2.0 license states
// Link for original repo LICENSE: https://github.com/cloudflare/privacypass-ts/blob/main/LICENSE.txt

import {
    Oprf,
    EvaluationRequest,
    randomPrivateKey,
    type SuiteID,
} from '@cloudflare/voprf-ts';

import {joinAll} from './util.js';
import {Buffer} from "buffer";

import {PSTServer} from "./PSTServer.js";

export class PSTResources {
    private static globalIssuer: PSTIssuer | null = null;

    private static getExpiryByEnv(env: string | undefined): number {
        if (env) {
            return parseInt(env, 10);
        } else {
            const now = new Date();
            const timeDelta = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
            return timeDelta.getTime();
        }
    }

    private static async getKeyByEnv(privateKeyEnv: string | undefined, publicKeyEnv: string | undefined, counter: number): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
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

    private static async initializeIssuer(): Promise<PSTIssuer> {
        const keys: Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; expiry: number }>[] = [];

        for (let i = 1; i <= 6; i++) {
            const privateKeyEnv = process.env[`PRIVATE_KEY${i}`];
            const publicKeyEnv = process.env[`PUBLIC_KEY${i}`];
            const expiryEnv = process.env[`EXPIRY${i}`];

            if (!privateKeyEnv || !publicKeyEnv) {
                if (i === 1) {
                    throw new Error(`Critical: PRIVATE_KEY1 or PUBLIC_KEY1 environment variables not set.`);
                } else {
                    console.warn(`Skipping key pair ${i}: environment variables not fully set.`);
                    continue;
                }
            }

            keys.push(
                this.getKeyByEnv(privateKeyEnv, publicKeyEnv, i).then((result) => ({
                    ...result,
                    expiry: this.getExpiryByEnv(expiryEnv),
                }))
            );

            console.log(`Loaded private key ${i} -> ${privateKeyEnv}`);
            console.log(`Loaded public key ${i} -> ${publicKeyEnv}`);
            console.log(`Loaded expiry key ${i} -> ${expiryEnv}`);
        }

        const resolvedKeys = await Promise.all(keys);
        return new PSTIssuer(resolvedKeys);
    }


    public static async getIssuer() {
        if (!this.globalIssuer) {
            this.globalIssuer = await this.initializeIssuer();
        }
        return this.globalIssuer;
    }
}


export class IssueRequest {

    constructor(
        public readonly blindedMsg: Uint8Array,
    ) {
        console.log(`Blinded Message Lenght: ${blindedMsg.length}`);
        if (blindedMsg.length !== 97) {
            throw new Error('invalid blinded message size');
        }
    }

    static deserialize(bytes: Uint8Array): IssueRequest {
        let offset = 0;
        const input = new DataView(bytes.buffer);

        const issue_count = input.getUint16(offset);
        console.log(`Issue Count: ${issue_count}`);
        offset += 2;

        const blindedMsg = new Uint8Array(input.buffer.slice(offset, input.byteLength));
        console.log(`blindedMsg: (${blindedMsg.length}) ${blindedMsg}`);

        return new IssueRequest(blindedMsg);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, 1);
        output.push(b);

        b = this.blindedMsg.buffer;
        output.push(b);

        return new Uint8Array(joinAll(output));
    }
}


export class IssueResponse {

    constructor(
        public readonly issued: number,
        public readonly keyID: number,
        public readonly signedNonce: Uint8Array,
        public readonly evaluateProof: Uint8Array,
    ) {
        if (signedNonce.length !== PSTServer.Ne ) {
            console.log(`Length ${signedNonce.length}, Ne ${PSTServer.Ne}`);
            throw new Error('evaluate_msg has invalid size');
        }
        if (evaluateProof.length !== 2 * PSTServer.Ns) {
            throw new Error('evaluate_proof has invalid size');
        }
    }

    /*
          This is the layout (in C) for the response for a IssueRequest (from the documentation)

          struct {
            uint16 issued;
            uint32 key_id;
            signedNonce signed[issued];
            opaque proof<1..2^16-1>; // Bytestring containing a serialized DLEQProof struct.
          } IssueResponse;
     */
    static deserialize(bytes: Uint8Array): IssueResponse {
        console.log('Deserializing IssueResponse');
        let offset = 0;
        const issued = (new DataView(bytes.buffer)).getUint16(offset, false);
        offset += 2;
        console.log(`Issued: ${issued}`);
        const keyID = (new DataView(bytes.buffer)).getUint32(offset, false);
        offset += 4;
        console.log(`KeyID: ${keyID}`);
        const signedNonce = new Uint8Array(bytes.slice(offset, offset + PSTServer.Ne));
        offset += PSTServer.Ne;
        const evaluateProof = new Uint8Array(bytes.slice(offset, offset + 2 * PSTServer.Ns));
        return new IssueResponse(issued, keyID, signedNonce, evaluateProof);
    }

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.issued);
        output.push(b);

        b = new ArrayBuffer(4);
        new DataView(b).setUint32(0, this.keyID);
        output.push(b);

        b = this.signedNonce.buffer;
        output.push(b);

        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.evaluateProof.buffer.byteLength);
        output.push(b);

        b = this.evaluateProof.buffer;
        output.push(b);

        let output_joined: Uint8Array;
        output_joined = new Uint8Array(joinAll(output));

        return output_joined;
    }
}

function extractKeyID(keyWithID: Uint8Array): number {
    const dataView = new DataView(keyWithID.buffer);
    return dataView.getUint32(0, false);
}

export function prependKeyID(keyID: number, byteArray: Uint8Array) {
    const resultBuffer = new ArrayBuffer(4 + byteArray.length);
    const dataView = new DataView(resultBuffer);
    dataView.setUint32(0, keyID, false);
    const originalKeyArray = new Uint8Array(byteArray);
    new Uint8Array(resultBuffer, 4).set(originalKeyArray);
    return new Uint8Array(resultBuffer);
}

export async function generatePublicKey(id: SuiteID, privateKey: Uint8Array) {
    const gg = Oprf.getGroup(id);
    const priv = gg.desScalar(privateKey);
    const pub = gg.mulGen(priv);
    return pub.serialize(false);
}


export function keyGenWithID(keyID: number): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    return new Promise(async (resolve) => {
        const privateKey = await randomPrivateKey(PSTServer.PST_SUITE);
        const publicKey = await generatePublicKey(PSTServer.PST_SUITE, privateKey);
        const privateKeyWithID = prependKeyID(keyID, privateKey);
        const publicKeyWithID = prependKeyID(keyID, publicKey);
        resolve({ privateKey: privateKeyWithID, publicKey: publicKeyWithID });
    });
}

function extractOriginalKey(keyWithID: Uint8Array): Uint8Array {
    return new Uint8Array(keyWithID.buffer, 4);
}

export class PSTIssuer {

    constructor(
        public keys: { publicKey: Uint8Array; privateKey: Uint8Array; expiry: number }[]
    ) {}

    findPSTServerByKeyID(keyID: number): PSTServer {
        const keyInfo = this.keys.find(({ privateKey }) => {
            const extractedKeyID = extractKeyID(privateKey);
            return extractedKeyID === keyID;
        });
        if (keyInfo) {
            const { privateKey } = keyInfo;
            const original_key = extractOriginalKey(privateKey);

            return new PSTServer(PSTServer.PST_SUITE, original_key);
        }
        else {
            throw new Error(`Invalid keyID`);
        }
    }

    async issueToken(encodedToken: string): Promise<string> {

        const decodedToken = Uint8Array.from(Buffer.from(encodedToken, 'base64'));
        const tokReq = IssueRequest.deserialize(decodedToken);
        const tokRes = await this.issue(tokReq);
        const tokResSerialized = tokRes.serialize();
        return Buffer.from(tokResSerialized).toString('base64');

    }

    async issue(tokReq: IssueRequest): Promise<IssueResponse> {
        console.log(`Total Keys: ${this.keys.length}`);
        const randomIndex = Math.floor(Math.random() * this.keys.length) + 1;
        console.log(`Key Selected: ${randomIndex}`);
        const server = this.findPSTServerByKeyID(randomIndex);
        const blindedElt = PSTServer.PST_GROUP.desElt(tokReq.blindedMsg);
        const evalReq = new EvaluationRequest([blindedElt]);
        const evaluation = await server.blindEvaluate(evalReq);

        if (evaluation.evaluated.length !== 1) {
            throw new Error('evaluation is of a non-single element');
        }

        // evaluateMsg should also contain the blinded message
        const evaluateMsg = evaluation.evaluated[0].serialize(false);

        if (typeof evaluation.proof === 'undefined') {
            throw new Error('evaluation has no DLEQ proof');
        }

        const evaluateProof = evaluation.proof.serialize();

        return new IssueResponse(1, randomIndex, evaluateMsg, evaluateProof);
    }


    async key_commitment_data() {
        const keysObject: Record<string, { Y: string; expiry: string }> = {};

        this.keys.forEach(({ publicKey, expiry }, index) => {
            const bufferKey = Buffer.from(publicKey);
            const base64Key = bufferKey.toString('base64');
            const expiryTimestampString = expiry.toString();

            keysObject[(index + 1).toString()] = { Y: base64Key, expiry: expiryTimestampString };
        });

        return {
            "PrivateStateTokenV1VOPRF": {
                "protocol_version": "PrivateStateTokenV1VOPRF",
                "id": 1,
                "batchsize": 1,
                "keys": keysObject
            }
        };
    }

}

export class RedeemerRequest {
    constructor(
        public readonly keyId: number,
        public readonly nonce: Uint8Array,
        public readonly ecPointW: Uint8Array,
        public readonly clientData: Uint8Array) {}

    static deserialize(bytes: Uint8Array): RedeemerRequest {
        console.log('Deserializing RedeemerRequest');
        // size of token is 241
        // [2 bytes for token size, token bytes, 2 bytes for client_data size, client_data bytes]

        let offset = 0;

        const tokenSize = new DataView(bytes.buffer).getUint16(offset, false);
        console.debug(`offset: ${offset} - Token Size: ${tokenSize}`);
        offset += 2;

        const keyId = new DataView(bytes.buffer).getUint32(offset, false);
        console.debug(`offset: ${offset} - keyId: ${keyId}`);
        offset += 4;

        const nonce = new Uint8Array(bytes.slice(offset, offset + 64));
        console.debug(`offset: ${offset} - nonce: ${nonce.slice(0, 4)} - size: ${nonce.length}`);
        offset += 64;

        const ecPointW = new Uint8Array(bytes.slice(offset, offset + PSTServer.Ne));
        console.debug(`offset: ${offset} - ecPointW: ${ecPointW.slice(0, 4)} - size: ${ecPointW.length}`);
        offset += PSTServer.Ne;

        const clientDataSize = new DataView(bytes.buffer).getUint16(offset, false);
        console.debug(`offset: ${offset} - Client Data Size: ${clientDataSize}`);

        offset += 2;
        const clientData = new Uint8Array(bytes.buffer, offset, clientDataSize); // last byte index is 240
        console.debug(`offset: ${offset} - Client Data: ${clientData}`);
        return new RedeemerRequest(keyId, nonce, ecPointW, clientData);
    }

}


export class RedeemerResponse {
    constructor(
        public readonly keyId: number,
        public readonly evaluated: Uint8Array,
        public readonly validated: boolean,
        public readonly redeemptionDate: number) {}

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.keyId);
        output.push(b);

        b = this.evaluated;
        output.push(b);

        // Serialize validated boolean
        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.validated ? 1 : 0);
        output.push(b);

        // Serialize redeemptionDate (Unix timestamp in milliseconds)
        b = new ArrayBuffer(8);
        new DataView(b).setFloat64(0, this.redeemptionDate);
        output.push(b);

        let output_joined: Uint8Array;
        output_joined = new Uint8Array(joinAll(output));

        return output_joined;
    }
}

export class PSTRedeemer {
    constructor(
    ) {}

    async redeemToken(tokenToRedeem: string): Promise<string> {

        const issuer = await PSTResources.getIssuer();
        const decodedToken = Uint8Array.from(Buffer.from(tokenToRedeem, 'base64'));
        const tokReq = RedeemerRequest.deserialize(decodedToken);
        let redeemRes = await this.redeem(tokReq, issuer);

        if ( ! redeemRes.validated ) {
            throw Error("Redemption Request is Invalid");
        }

        return Buffer.from(redeemRes.serialize()).toString('base64');
    }

    async redeem(tokReq: RedeemerRequest, issuer: PSTIssuer) {

        let validated = false;

        const server = issuer.findPSTServerByKeyID(tokReq.keyId);

        try {
            // Hash nonce into an elliptic curve group element
            let inputElement = await server.evaluate(tokReq.nonce);

            const point = PSTServer.PST_GROUP.desElt(tokReq.ecPointW);
            const compressedPoint = point.serialize(true)

            validated = Buffer.from(inputElement).equals(Buffer.from(compressedPoint));
        } catch (e: any) {
            console.error(e);
            throw e;
        }

        return new RedeemerResponse(tokReq.keyId, tokReq.clientData, validated, Date.now());
    }
}