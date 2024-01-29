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

function generatePublicKey(id, privateKey) {
    const gg = voprf.Oprf.getGroup(id);
    const priv = gg.desScalar(privateKey);
    const pub = gg.mulGen(priv);
    return pub.serialize(false);
}

async function main() {
    const args = process.argv.slice(2); // Exclude node executable and script name
    const keyID = parseInt(args[0]);

    if (isNaN(keyID) || keyID < 0) {
        console.error('Invalid keyID. Please provide a non-negative integer keyID.');
        process.exit(1);
    }

    const private_key = await voprf.randomPrivateKey(suite);
    const public_key = await generatePublicKey(suite, private_key);
    console.log(`length: ${private_key.length}, ${private_key}`);
    console.log(public_key);

    const privateKey = prependKeyID(keyID, private_key);
    const publicKey = prependKeyID(keyID, public_key);

    let base64PrivateKey = Buffer.from(privateKey).toString('base64');
    let base64PublicKey = Buffer.from(publicKey).toString('base64');

    console.log(`Private Key: ${base64PrivateKey}`);
    console.log(`Public Key: ${base64PublicKey}`);
}

main();
