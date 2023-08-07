# swift-mini-rsa-encryption

**This repository is now archived, preserved for historical curiosity only. DO NOT USE THIS CODE. [SwiftCrypto 2.6.0](https://github.com/apple/swift-crypto) and later has this functionality in much improved form, as was always intended to happen.**

~~Embeds BoringSSL sufficiently to expose just the RSA encrypt/decrypt functions. This is a temporary package that will hopefully go away if and when SwiftCrypto's _CryptoExtras adds the same APIs.~~

~~This package is a distillation of https://github.com/gwynne/swift-crypto/tree/gwynne/rsa-encrypt-decrypt down to _just_ the RSA encrypt/decrypt API, with almost all of the original swift-crypto code removed and the embedded BoringSSL renamed to avoid conflicts. Since it is impractical to use the forked swift-crypto repo when other packages in the overall dependency graph refer to the original upstream repository, this package is intended to enable usage of the new API with (almost) exactly the same interface (except for the module name) - at the unfortunate and painful cost of an additional copy of BoringSSL to build - until such time as swift-crypto accepts [the relevant PR](https://github.com/apple/swift-crypto/pull/125), rejects it (in which case this package will most likely be subsumed into some other solution), or provides an alternative solution.~~

~~## **IMPORTANT!!!**~~

~~The primitive RSA encrypt/decrypt operations are _not_ suitable for general use. These are obsolete, _very_ easily misused operations (as with RSA cryptography in general), and the effort to make them avaiable through this package has been made solely for the sake of supporting pre-existing implementations in common use which cannot be avoided, replaced, or updated. DO NOT USE THIS PACKAGE UNLESS YOU HAVE A VERY GOOD REASON TO DO SO! "MySQL 8.0's wire protocol for authentication relies on the client performing an RSA encryption operation" is a good reason - "I know what RSA is and don't feel like learning this elliptic curve stuff" is not (in fact, it's a really _bad_ reason).~~

~~## Just to be perfectly clear...~~

~~There will never be any "stable" (1.0.0 or greater) releases of this package. Once it has served its purpose, it will be deleted, _not_ archived. The author of this package wishes to emphasize in the strongest possible terms that this is a stopgap measure **ONLY** and is not guaranteed to work properly for any use case other than that it was built specifically for. Don't use it. Seriously, don't. You are responsible for any and all consequences that stem from making any use of this package.~~
