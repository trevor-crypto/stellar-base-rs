//! A custom signer using ed25519-dalek (instead of sodiumoxide)

use ed25519_dalek::{Keypair, Signer};
use rand::rngs::OsRng;
use stellar_base::crypto::{EddsaSigner, PublicKey, Signature};

struct DalekKeyPair {
    pub_key: PublicKey,
    key_pair: Keypair,
}

impl EddsaSigner for DalekKeyPair {
    fn public_key(&self) -> PublicKey {
        self.pub_key
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.key_pair.sign(message)
    }

    fn verify(&self, signature: &Signature, data: &[u8]) -> bool {
        self.key_pair
            .verify(data, signature)
            .map_or(false, |_| true)
    }
}

impl Default for DalekKeyPair {
    fn default() -> DalekKeyPair {
        let mut rng = OsRng {};
        let key_pair = Keypair::generate(&mut rng);
        let pub_key: ed25519_dalek::PublicKey = (&key_pair.secret).into();

        DalekKeyPair {
            pub_key: PublicKey(pub_key.to_bytes()),
            key_pair,
        }
    }
}

pub fn main() {
    let keys = DalekKeyPair::default();

    let msg = b"test message";
    let sig = keys.sign(msg);
    assert!(keys.verify(&sig, msg));
}
