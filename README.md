# Private State Tokens

Typescript library implementing Private State Token API (https://wicg.github.io/trust-token-api/)

This library depends on [Cloudflare's voprf-ts](https://github.com/cloudflare/voprf-ts) tested implementation to compute the Scalars and transformations. 

# Security Disclaimer
🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. We recommend to take caution before using this library in a production application since part of its content is experimental. All security issues must be reported, please notify us immediately.

## Install Dependencies and Build

```
npm install
npm run build
```

## Sample Issuer

> Sample has been built using Express Library

- Start Sample Server

  ```
  npm run example
  ```

- Running with Docker

  - build
    ```
    docker-compose build
    ```
  - start
    ```
    docker-compose up
    ```

#### Running with Static Key-Pair and Expiration

- Generate up to 6 KeyPairs

  ```
  node bin/voprf_gen_keys.cjs 1
  node bin/voprf_gen_keys.cjs 2
  # Keep creating until node bin/voprf_gen_keys.cjs 6
  ```

- Export Keys as Environment Variables

  ```
  export PRIVATE_KEY1=<BASE64 PRIVATE KEY 1 GENERATED PREVIOUSLY>
  export PUBLIC_KEY1=<BASE64 PUBLIC KEY 1 GENERATED PREVIOUSLY>
  export PRIVATE_KEY2=<BASE64 PRIVATE KEY 2 GENERATED PREVIOUSLY>
  export PUBLIC_KEY2=<BASE64 PUBLIC KEY 2 GENERATED PREVIOUSLY>
  # Keep defining until PRIVATE_KEY6 and PUBLIC_KEY6
  ```

- Export Key Expiration as Environment Variable

  ```
  export EXPIRY1=1709509052048
  export EXPIRY2=1709994102048
  # Keep defining until EXPIRY6
  ```

> If running with **Docker** define those variables in docker-compose.yaml or -e argument for docker inline

### Endpoints

- Key Commitment Endpoint

  ```
  curl http://localhost:3000/.well-known/trust-token/key-commitment
  ```

## Resources, Libraries and Specs:

- [Google Privacy Sandbox - Private State Tokens](https://developers.google.com/privacy-sandbox/protections/private-state-tokens)
- [Private State Tokens API Spec](https://wicg.github.io/trust-token-api/)
- [Privacy Pass Issuance Protocol Spec](https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-10.html)
- [Oblivious Pseudorandom Functions (OPRFs) Spec](https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html)
- [Batched Tokens Issuance Protocol Spec](https://www.ietf.org/archive/id/draft-robert-privacypass-batched-tokens-01.html)
- [CloudFlare - Privacy Pass TypeScript Library](https://github.com/cloudflare/privacypass-ts/)
- [CloudFlare - VOPRF TypeScript Library](https://github.com/cloudflare/voprf-ts)

## How to use this library

### Token Issuance

To issue a token, you must check for the request header `sec-private-state-token`, after verify it is present and it is not null or empty you can use the Issuer class like the code bellow:

```typescript
import { PSTRedeemer, PSTResources } from "@sec4you/pst";

const sec_private_state_token = req.headers[
  "sec-private-state-token"
] as string;
if (sec_private_state_token && !sec_private_state_token.match(BASE64FORMAT)) {
  return res.sendStatus(400);
}

try {
  let issuer = await PSTResources.getIssuer();
  const token = await issuer.issueToken(sec_private_state_token);

  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html");
  res.append("sec-private-state-token", token);
  res.setHeader("Sec-Private-State-Token", token);
  res.write("Issuing tokens.");
  res.send();

  return res.end();
} catch (e: any) {
  // deal with the error as you see fit
  console.error("Error issuing PST", e);
  return res.sendStatus(500);
}
```

### Token Redeemption

To redeem an issued token the process is similar, your endpoint must check for the request header `sec-private-state-token`, if it is present and it is not null or empty you can proceed to the redeemption

```typescript
import { PSTRedeemer, PSTResources } from "@sec4you/pst";

try {
  const redemptionToken = req.headers["sec-private-state-token"] as string;

  if (redemptionToken && !redemptionToken.match(BASE64FORMAT)) {
    return res.sendStatus(400);
  }

  const redeemer = new PSTRedeemer();

  // This call will throw an Error if the token is invalid
  const resToken = await redeemer.redeemToken(redemptionToken);

  res.statusCode = 200;
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.append("sec-private-state-token", resToken);
  res.write("Token redeemed.");
  return res.send();
} catch (e) {
  // deal with the error as you see fit
  console.error(`Error on redemption: ${e}`);
  return res.sendStatus(400);
}
```


