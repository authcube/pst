import {Oprf, type SuiteID, VOPRFServer} from "@cloudflare/voprf-ts";
import type {CryptoProviderArg} from "@cloudflare/voprf-ts/lib/cjs/src/cryptoImpl";

export class MyVOPRFServer extends VOPRFServer {
    constructor(suite: SuiteID, privateKey: Uint8Array, ...arg: CryptoProviderArg) {
        super(suite, privateKey, ...arg);
    }

    async evaluate(input: Uint8Array): Promise<Uint8Array> {
        let secret = this.privateKey;

        const P = await this.group.hashToGroup(input, this.getDST(Oprf.LABELS.HashToGroupDST));
        if (P.isIdentity()) {
            throw new Error('InvalidInputError');
        }

        const evaluated = await this.doBlindEvaluation(P, secret);

        return evaluated.serialize(true);
    }
}