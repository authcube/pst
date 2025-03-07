import { PSTResources } from "../pst";

const sec_private_state_token = "AAEEN+DbP01bjtXDPFhg2bR2Os9CPKlXRFvEqQ92MlhTPQC303uzQTXNF1e4i0tNF79gsomq7hLt6ieIBVxYKdqjN5ISrlDg0S7lnhcKA1TVdbjyrMZhNaw3s109mkxfbPeI";

process.env[`PRIVATE_KEY1`] = "AAAAAf1H43e6jjpkurLwikOhxcifykmxvhnDMSjSxjdLJ1xZjmAldnqxVfnnkdE4cTwbYA";
process.env[`PUBLIC_KEY1`] = "AAAAAQS7kAjekfTKQSeiaXdpcophFhOWKzQgzzBgwiB/whnrOR2WZes9+UpioO8UtYfCWtnQun2fV04jhQRrCes3cC3cdpd0fsTqR/eLG3cNI1SF/UiFn/UEHQhai7/dnhMMxRU\\=";
process.env[`EXPIRY1`] = "4133894400000000"; // 2100-12-31T00:00:00.000Z

(async () => {
    try {

        let issuer = await PSTResources.getIssuer();
        const token = await issuer.issueToken(sec_private_state_token);
        console.log(token);

    } catch (err) {
        console.error("Failed to initialize issuer:", err);
    }
})();
