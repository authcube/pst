# Private State Tokens

Typescript library implementing Private State Token API (https://wicg.github.io/trust-token-api/)


## Install Dependencies and Build

```
npm install
npm run build
```


## Run Example Server

  > Example has been built using Express Library

  - Generate KeyPair

    ```
    node bin/voprf_gen_keys.cjs
    ```

  - Export Keys as Environment Variables 

    ```
    export PRIVATE_KEY=<BASE64 PRIVATE KEY GENERATED PREVIOUSLY>
    export PUBLIC_KEY=<BASE64 PUBLIC KEY GENERATED PREVIOUSLY>
    ```

  - Export Key Expiration as Environment Variable

    > Define the timestamp that the Key will expire on the key-commitment endpoint

    ```
    export EXPIRY=1708123052048
    ```

### Example Endpoints

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


## TO-DO

- Library
  - Accept Multiple Keys on Issuer (max 6 from spec)
  - Implement Token Issuance
  - Implement Token Redemption
- Example
  - Issuance Endpoint
  - Redemption Endpoint
