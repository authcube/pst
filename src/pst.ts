// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0

// Original copy: https://github.com/cloudflare/privacypass-ts/blob/main/src/priv_verif_token.ts
// the original copy has been modified in order to implement Private State Tokens API
// Same copyrights banner from the original copy has been preserved as Apache2.0 license states
// Link for original repo LICENSE: https://github.com/cloudflare/privacypass-ts/blob/main/LICENSE.txt

import {
    Oprf,
    generateKeyPair,
    type DLEQParams,
    type Group,
    type SuiteID,
    type HashID,
} from '@cloudflare/voprf-ts';

import {
    type TokenTypeEntry
} from "@cloudflare/privacypass-ts";
import {Buffer} from "buffer";

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
const VOPRF_EXTRA_PARAMS: VOPRFExtraParams = {
    suite: VOPRF_SUITE,
    group: VOPRF_GROUP,
    Ne: VOPRF_GROUP.eltSize(),
    Ns: VOPRF_GROUP.scalarSize(),
    Nk: Oprf.getOprfSize(VOPRF_SUITE),
    hash: VOPRF_HASH,
    dleqParams: {
        gg: VOPRF_GROUP,
        hashID: VOPRF_HASH,
        hash: Oprf.Crypto.hash,
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

function extractKeyID(keyWithID: Uint8Array): number {
    const dataView = new DataView(keyWithID.buffer);
    return dataView.getUint32(0, false);
}

export function prependKeyID(keyID: number, originalKey: Uint8Array) {
    const resultBuffer = new ArrayBuffer(4 + originalKey.length);
    const dataView = new DataView(resultBuffer);
    dataView.setUint32(0, keyID, false);
    const originalKeyArray = new Uint8Array(originalKey);
    new Uint8Array(resultBuffer, 4).set(originalKeyArray);
    return new Uint8Array(resultBuffer);
}

export function keyGenWithID(keyID: number): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
    return new Promise(async (resolve) => {
        const { privateKey, publicKey } = await generateKeyPair(VOPRF.suite);
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

    findPrivateKey(keyID: number): Uint8Array | undefined {
        const keyInfo = this.keys.find(({ privateKey }) => {
            const extractedKeyID = extractKeyID(privateKey);
            return extractedKeyID === keyID;
        });

        if (keyInfo) {
            const { privateKey } = keyInfo;
            return extractOriginalKey(privateKey);
        }

        return undefined;
    }

    async key_commitment_data() {
        const keysObject: Record<string, { Y: string; expiry: number }> = {};

        this.keys.forEach(({ publicKey, expiry }, index) => {
            const bufferKey = Buffer.from(publicKey);
            const base64Key = bufferKey.toString('base64');
            keysObject[(index + 1).toString()] = { Y: base64Key, expiry };
        });

        return {
            "PrivateStateTokenV1VOPRF": {
                "protocol_version": "PrivateStateTokenV1VOPRF",
                "id": "1",
                "batchsize": "1",
                "keys": keysObject
            }
        };
    }
}