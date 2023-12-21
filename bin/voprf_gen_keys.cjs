const voprf = require('@cloudflare/voprf-ts');

const suite = voprf.Oprf.Suite.P384_SHA384;

function prependKeyID(keyID, originalKey) {
    const resultBuffer = new ArrayBuffer(4 + originalKey.length);
    const dataView = new DataView(resultBuffer);
    dataView.setUint32(0, keyID, false);
    const originalKeyArray = new Uint8Array(originalKey);
    new Uint8Array(resultBuffer, 4).set(originalKeyArray);
    return new Uint8Array(resultBuffer);
}

async function main() {
    const keyID = 1;
    const keypair = await voprf.generateKeyPair(suite);
    console.log(keypair);
    const privateKey = prependKeyID(keyID, keypair.privateKey);
    const publicKey = prependKeyID(keyID, keypair.publicKey);
    let base64PrivateKey = Buffer.from(privateKey).toString('base64');
    let base64PublicKey = Buffer.from(publicKey).toString('base64');
    console.log(`Private Key: ${base64PrivateKey}`);
    console.log(`Public Key: ${base64PublicKey}`);
}
main();
