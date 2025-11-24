# Migration Guide: Upgrading from `cggmp21 v0.6` to `cggmp24 v0.7`

This guide provides the necessary steps to migrate your project from the older `cggmp21` protocol
implementation to the latest `cggmp24` version. This upgrade is essential to align with the most
recent CGGMP24 paper revision.

There's many breaking changes in this release, so for convinience, we split them into several `alpha`
releases. This instruction guides you through updating `cggmp21 v0.6` → `cggmp24 v0.7.0-alpha.1` →
`v0.7.0-alpha.2` → `v0.7.0-alpha.3`.

## Step 1: Update `Cargo.toml` to use `cggmp24 v0.7.0-alpha.1`
The first step is to update your project's dependencies. Modify your `Cargo.toml` file to point to the
new version of the library.

Replace the existing line for `cggmp21` with the following:

```toml
[dependencies]
cggmp24 = "0.7.0-alpha.1"
```

If your `Cargo.toml` references `cggmp21-keygen` or `paillier-zk` crates, do the same with them:
* `cggmp21-keygen` becomes `cggmp24-keygen`
* New version for both crates is `0.7.0-alpha.1`

## Step 2: Update Code References
Next, you need to update all references to cggmp21 within your Rust source code. E.g. `cggmp21::keygen(eid, i, n)`
should become `cggmp24::keygen(eid, i, n)`.

You can perform this replacement automatically across your entire project by running the following
shell command from your project's root directory:

```bash
find . -type f -name "*.rs" -exec sed -i -E 's/\bcggmp21\b/cggmp24/g; s/\bcggmp21_keygen\b/cggmp24_keygen/g; s/\bCGGMP21\b/CGGMP24/g' {} +
```

This command will find all .rs files and replace:
* `cggmp21` with `cggmp24`
* `cggmp21_keygen` with `cggmp24_keygen`
* `CGGMP21` with `CGGMP24`

See git diff to verify that command did not introduce any unwanted changes.

## Step 3: Auxiliary Data Re-generation
Due to breaking changes in the protocol, auxiliary data (`cggmp24::key_share::AuxInfo`) generated in
`cggmp21` is no longer supported. You must re-generate this data.

### New Auxiliary Data Generation

Run the `cggmp24::aux_info_gen()` protocol to generate new auxiliary data.

Important: This protocol is computationally intensive and may take several minutes to complete,
depending on your hardware. However, as recommended, you should use the same auxiliary data for all
keys. This makes it a one-time setup cost.

### Recovering Existing Key Shares

If you have stored a complete `cggmp24::KeyShare` from a previous version, you will not be
able to deserialize it directly. To recover the essential data from serialized key shares,
you need to extract the "incomplete" key share from them. To do that, you can use the
`cggmp24::key_share::cggmp21_compat::ExtractCoreShare` utility structure: it provides a
`serde::Deserialize` implementation that is compatible with the `cggmp21::KeyShare` format. This
allows you, while still using the new version of the library, to read an old version of a key share,
and extract the "core".

Once you have the core key share, you can combine it with your newly generated auxiliary data to
reconstruct a complete, compatible key share.

## Step 4: Compile and Test

At this point, your project should compile and work perfectly fine with `cggmp24 v0.7.0-alpha.1`.
Make sure it is the case:

```bash
cargo clean
cargo test
```

If there are issues, please fix them before proceeding to the next step.

## Step 5: Update `Cargo.toml` to use `cggmp24 v0.7.0-alpha.2`
Update version of `cggmp24`:

```toml
[dependencies]
cggmp24 = "0.7.0-alpha.2"
```

## Step 6: Presignatures API changes

From this version, our API explicitly prohibits using presignatures:
* With "raw signing" (when we sign a hash of message, and original message is not known to the signer)
* With HD wallet derivation

In both cases, attacks have been found that break or significantly decrease security of the signing.
Read the [vulnerability disclosure][vuln-disclosure] to learn more about these attacks.

We changed API to prohibit "raw signing" with presignatures: now we provide `ccgmp24::{DataToSign,
PrehashedDataToSign}`. `DataToSign` can only be constructed when original message is provided, by
using `DataToSign::{digest, from_digest}` constructors that take an original message and a hash
function, and they perform hashing internally.

Now signing using presignature, i.e. `cggmp24::signing::Presignature::issue_partial_signature` **only**
accepts `DataToSign`, which serves as a type-guard that original message has been observed.

Otherwise, for regular signing via `cggmp24::signing().sign(...)` you can provide both `DataToSign` and
`PrehashedDataToSign` (the latter can be constructed from any scalar/hash), as `.sign(..)` accepts
`&dyn AnyDataToSign`.

Note: although highly discouraged, you may bypass API type-guards and convert `PrehashedDataToSign`
into `DataToSign`. To do that, you need to enable a feature `insecure-assume-preimage-known` in
`cggmp24` crate and call method `PrehashedDataToSign::insecure_assume_preimage_known`. Use it
only if you can completely trust the source of the prehashed data, and beware of possible attack
described in the [blog][vuln-disclosure].

Lastly, `Presignature::{set_derivation_path, set_derivation_path_with_algo}` methods have been removed to
address second attack.

[vuln-disclosure]: https://www.dfns.co/article/cggmp21-vulnerabilities-patched-and-explained

Update your code to comply with the new API.

## Step 7: Compile and Test

At this point, your project should compile and work perfectly fine with `cggmp24 v0.7.0-alpha.2`.
Make sure it is the case:

```bash
cargo clean
cargo test
```

If there are issues, please fix them before proceeding to the next step.

