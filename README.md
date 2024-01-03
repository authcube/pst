# Private State Tokens

Typescript library implementing Private State Token API (https://wicg.github.io/trust-token-api/)


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


## TO-DO

- Library
  - Implement Token Issuance
  - Implement Token Redemption
- Example
  - Issuance Endpoint
  - Redemption Endpoint
