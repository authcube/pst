import {type HashID, Oprf, type SuiteID, VOPRFServer} from "@cloudflare/voprf-ts";
// @ts-ignore
import type { CryptoProviderArg } from "@cloudflare/voprf-ts/lib/cjs/src/cryptoImpl";


export class PSTServer extends VOPRFServer {

    public static readonly PST_SUITE = Oprf.Suite.P384_SHA384;
    public static readonly PST_GROUP = Oprf.getGroup(this.PST_SUITE);
    public static readonly PST_HASH = Oprf.getHash(this.PST_SUITE) as HashID;

    public static readonly Ne = this.PST_GROUP.eltSize(false);
    public static readonly Ns = this.PST_GROUP.scalarSize();


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