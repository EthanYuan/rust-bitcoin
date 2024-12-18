## Rust Dogecoin

This project is a fork of [rust-bitcoin](./rust-bitcoin.md), modified to support [Dogecoin] SPV (Simplified Payment Verification) on [CKB] (Nervos Blockchain). It retains most of the original rust-bitcoin functionality, with the following specific changes:

- Dogecoin Header Deserialization: Modifications to handle the deserialization of Dogecoin headers.
- AuxPow Validation: Added logic to validate AuxPow (Auxiliary Proof-of-Work) as required by Dogecoin.

## Projects Using This Library

- [ckb-dogecoin-spv](https://github.com/ckb-devrel/ckb-dogecoin-spv)
- [ckb-dogecoin-spv-service](https://github.com/ckb-devrel/ckb-dogecoin-spv-service)

[Dogecoin]: https://dogecoin.org
[Bitcoin]: https://bitcoin.org
[CKB]: https://github.com/nervosnetwork/ckb