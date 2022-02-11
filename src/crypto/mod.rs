//! Cryptographic functions.

mod public_key;
mod signature;
#[cfg(feature = "sodium_oxide")]
mod sodium_oxide;
mod strkey;

use sha2::Digest;

pub use self::public_key::{MuxedAccount, MuxedEd25519PublicKey, PublicKey};
pub use self::signature::*;
pub use self::strkey::*;
pub use ed25519::Signature;
#[cfg(feature = "sodium_oxide")]
pub use sodium_oxide::*;

/// Compute sha256 hash of `m`.
pub fn hash(m: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(&m).to_vec()
}

pub trait EddsaSigner {
    /// Returns this key's PublicKey
    fn public_key(&self) -> PublicKey;

    /// Sign the `message`.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Sign the `message` together with the signature hint.
    fn sign_decorated(&self, message: &[u8]) -> DecoratedSignature {
        let hint = self.signature_hint();
        let signature = self.sign(message);
        DecoratedSignature::new(hint, signature)
    }

    /// Return the signature hint, that is the last 4 bytes of the public key.
    fn signature_hint(&self) -> SignatureHint {
        SignatureHint::from_public_key(&self.public_key())
    }

    /// Verifies the `signature` against the `data`.
    /// Returns `true` if the signature is valid, `false` otherwise.
    fn verify(&self, signature: &Signature, data: &[u8]) -> bool;
}
