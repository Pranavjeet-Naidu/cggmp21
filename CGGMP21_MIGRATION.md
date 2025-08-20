# Migration Guide: Upgrading from `cggmp21 v0.6` to `cggmp24 v0.7`

This guide provides the necessary steps to migrate your project from the older `cggmp21` protocol
implementation to the latest `cggmp24` version. This upgrade is essential to align with the most
recent CGGMP24 paper revision.

## Step 1: Update `Cargo.toml`
The first step is to update your project's dependencies. Modify your `Cargo.toml` file to point to the
new version of the library.

Replace the existing line for `cggmp21` with the following:

```toml
[dependencies]
cggmp24 = "0.7"
```

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

## Step 4: Finalize and Test

After having followed all the instructions above, you can clean your build artifacts and run your
project's tests to ensure the migration was successful.

```bash
cargo clean
cargo test
```

If the code bulds, all tests pass, then your migration is complete. You are now using the latest
`cggmp24` implementation.
