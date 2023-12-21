const voprf = require('@cloudflare/voprf-ts');

const suite = voprf.Oprf.Suite.P384_SHA384;

global.crypto = require("crypto");

async function main() {
    const keypair = await voprf.generateKeyPair(suite);
    console.log(keypair);
    const privateKey = keypair.privateKey;
    const publicKey = keypair.publicKey;
    let base64PrivateKey = Buffer.from(privateKey).toString('base64');
    let base64PublicKey = Buffer.from(publicKey).toString('base64');
    console.log(`Private Key: ${base64PrivateKey}`);
    console.log(`Public Key: ${base64PublicKey}`);
}
main();
