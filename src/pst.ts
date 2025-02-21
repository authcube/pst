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
    VOPRFServer,
    // DLEQProof,
    type DLEQParams,
    type Group,
    type SuiteID,
    type HashID, VOPRFClient
} from '@cloudflare/voprf-ts';

import {joinAll} from './util.js';
import {Buffer} from "buffer";
import {
  type TokenTypeEntry
} from '@cloudflare/privacypass-ts'


export interface VOPRFExtraParams {
    suite: SuiteID;
    group: Group;
    Ne: number;
    Ns: number;
    Nk: number;
    hash: HashID;
    dleqParams: DLEQParams;
}



const VOPRF_SUITE = Oprf.Suite.P384_SHA384;
const VOPRF_GROUP = Oprf.getGroup(VOPRF_SUITE);
const VOPRF_HASH = Oprf.getHash(VOPRF_SUITE) as HashID;
// @ts-ignore
// @ts-ignore
// @ts-ignore
// @ts-ignore
const VOPRF_EXTRA_PARAMS: VOPRFExtraParams = {
    suite: VOPRF_SUITE,
    group: VOPRF_GROUP,
    Ne: VOPRF_GROUP.eltSize(false),
    Ns: VOPRF_GROUP.scalarSize(),
    // Nk: Oprf.getOprfSize(VOPRF_SUITE),
    Nk: 64,
    hash: VOPRF_HASH,

    dleqParams: {
        gg: VOPRF_GROUP,
        hashID: VOPRF_HASH,
        // @ts-ignore
        hash: Oprf.Crypto.hash,
        // @ts-ignore
        dst: '',
    },
} as const;

export const VOPRF: Readonly<TokenTypeEntry> & VOPRFExtraParams = {
    value: 0x0001,
    name: 'VOPRF (P-384, SHA-384)',
    Nid: 32,
    publicVerifiable: false,
    publicMetadata: false,
    privateMetadata: false,
    ...VOPRF_EXTRA_PARAMS,
} as const;

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

        // const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + input.byteLength));
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
  /*
        struct {
          uint16 issued;
          uint32 key_id;
          signedNonce signed[issued];
          opaque proof<1..2^16-1>; // Bytestring containing a serialized DLEQProof struct.
        } IssueResponse;
   */
    constructor(
        public readonly issued: number,
        public readonly keyID: number,
        public readonly signedNonce: Uint8Array,
        public readonly evaluateProof: Uint8Array,
    ) {
        if (signedNonce.length !== VOPRF.Ne ) {
            console.log(`Length ${signedNonce.length}, Ne ${VOPRF.Ne}`);
            throw new Error('evaluate_msg has invalid size');
        }
        if (evaluateProof.length !== 2 * VOPRF.Ns) {
            throw new Error('evaluate_proof has invalid size');
        }
    }

    static deserialize(bytes: Uint8Array): IssueResponse {
        console.log('Deserializing IssueResponse');
        let offset = 0;
        const issued = (new DataView(bytes.buffer)).getUint16(offset, false);
        offset += 2;
        console.log(`Issued: ${issued}`);
        const keyID = (new DataView(bytes.buffer)).getUint32(offset, false);
        offset += 4;
        console.log(`KeyID: ${keyID}`);
        const signedNonce = new Uint8Array(bytes.slice(offset, offset + VOPRF.Ne));
        offset += VOPRF.Ne;
        const evaluateProof = new Uint8Array(bytes.slice(offset, offset + 2 * VOPRF.Ns));
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

export function generatePublicKey(id: SuiteID, privateKey: Uint8Array) {
    const gg = Oprf.getGroup(id);
    const priv = gg.desScalar(privateKey);
    const pub = gg.mulGen(priv);
    return pub.serialize(false);
}


export function keyGenWithID(keyID: number): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    return new Promise(async (resolve) => {
        const privateKey = await randomPrivateKey(VOPRF.suite);
        const publicKey = await generatePublicKey(VOPRF.suite, privateKey);
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

    findServerByKeyID(keyID: number): VOPRFServer {
        const keyInfo = this.keys.find(({ privateKey }) => {
            const extractedKeyID = extractKeyID(privateKey);
            return extractedKeyID === keyID;
        });
        if (keyInfo) {
            const { privateKey } = keyInfo;
            const original_key = extractOriginalKey(privateKey);

            return new VOPRFServer(VOPRF.suite, original_key);
        }
        else {
            throw new Error(`Invalid keyID`);
        }
    }

    findClientByKeyID(keyID: number): VOPRFClient {
        const keyInfo = this.keys.find(({ publicKey }) => {
            const extractedKeyID = extractKeyID(publicKey);
            return extractedKeyID === keyID;
        });
        if (keyInfo) {
            const { publicKey } = keyInfo;
            const original_key = extractOriginalKey(publicKey);

            return new VOPRFClient(VOPRF.suite, original_key);
        }
        else {
            throw new Error(`Invalid keyID`);
        }
    }

    async issue(tokReq: IssueRequest): Promise<IssueResponse> {
        console.log(`Total Keys: ${this.keys.length}`);
        const randomIndex = Math.floor(Math.random() * this.keys.length) + 1;
        console.log(`Key Selected: ${randomIndex}`);
        const server = this.findServerByKeyID(randomIndex);
        const blindedElt = VOPRF.group.desElt(tokReq.blindedMsg);
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

        // return new IssueResponse(1, randomIndex, evaluateMsg, evaluateProof);
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
        console.log(`offset: ${offset} - Token Size: ${tokenSize}`);
        offset += 2;

        const keyId = new DataView(bytes.buffer).getUint32(offset, false);
        console.log(`offset: ${offset} - keyId: ${keyId}`);
        offset += 4;

        const nonce = new Uint8Array(bytes.slice(offset, offset + 64));
        console.log(`offset: ${offset} - nonce: ${nonce.slice(0, 4)} - size: ${nonce.length}`);
        offset += 64;

        // const ecPointW = new Uint8Array(bytes.slice(offset, offset + 96));
        const ecPointW = new Uint8Array(bytes.slice(offset, offset + VOPRF.Ne));
        console.log(`offset: ${offset} - ecPointW: ${ecPointW.slice(0, 4)} - size: ${ecPointW.length}`);
        // offset = tokenSize+2; // must be +2 because of the first 2 bytes on the 'bytes' data
        offset += VOPRF.Ne;

        const clientDataSize = new DataView(bytes.buffer).getUint16(offset, false);
        console.log(`offset: ${offset} - Client Data Size: ${clientDataSize}`);

        offset += 2;
        const clientData = new Uint8Array(bytes.buffer, offset, clientDataSize); // last byte index is 240
        console.log(`offset: ${offset} - Client Data: ${clientData}`);
        return new RedeemerRequest(keyId, nonce, ecPointW, clientData);
    }

    // serialize(): Uint8Array {
    //     const output = new Uint8Array();
    //
    //     return output;
    // }
}


export class RedeemerResponse {
    constructor(
        public readonly keyId: number,
        public readonly evaluated: Uint8Array,
    ) {}

    serialize(): Uint8Array {
        const output = new Array<ArrayBuffer>();

        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.keyId);
        output.push(b);

        b = this.evaluated;
        output.push(b);

        let output_joined: Uint8Array;
        output_joined = new Uint8Array(joinAll(output));

        return output_joined;
    }
}

export class PSTRedeemer {
    constructor(
    ) {}

    async redeem(tokReq: RedeemerRequest, issuer: PSTIssuer) {

        const server = issuer.findServerByKeyID(tokReq.keyId);

        try {
            // Hash nonce into an elliptic curve group element
            let inputElement = await server.evaluate(tokReq.nonce);

            const point = VOPRF.group.desElt(tokReq.ecPointW);
            const compressedPoint = point.serialize(true)

            // Check if the length is 48 instead of 49
            if (inputElement.length === 48) {
                // Manually prepend `0x03`
                inputElement = Buffer.concat([Buffer.from([0x03]), Buffer.from(inputElement)]);
            }

            // Compare issued element with client's W value
            if (!Buffer.from(inputElement).equals(Buffer.from(compressedPoint))) {
                throw new Error('InvalidInputError: Issued element does not match client\'s W value');
            }

            // Construct redemption record based on client_data
            // const redemptionRecord = {
            //     timestamp: Date.now(),
            //     clientData: tokReq.clientData,
            //     validated: true
            //     // Add other fields as needed for your application
            // };
            //
            // return redemptionRecord;
        } catch (e: any) {
            console.error(e);
            throw e;
        }

        // TODO remove verifyFinalize

        return new RedeemerResponse(tokReq.keyId, tokReq.clientData);
    }
}