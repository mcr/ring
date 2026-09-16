use crate::{ec, rsa, signature::EcdsaKeyPair, error, io::der};
use crate::rand;
use crate::signature::{self, EcdsaSigningAlgorithm};
use untrusted;
use pem;

#[derive(Debug)]
pub enum GenericKeyPair {
    EcdsaKeyPair(EcdsaKeyPair, &'static EcdsaSigningAlgorithm),
    RsaKeyPair(rsa::KeyPair),
    Ed25519KeyPair(ec::KeyPair)
}

impl GenericKeyPair {
    /// Constructs a generic KeyPair from a PEM encoded PKCS8 file
    ///
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, error::KeyRejected> {
        let pemthing = pem::parse(pem).unwrap();
        return Self::from_pkcs8(pemthing.contents())
    }

    /// Constructs a generic KeyPair from a PKCS8 file.
    ///
    /// This method does not care what kind of private key it is, and
    /// will parse the DER to identify the key type, and then will
    /// call an appropriate function to parse it.
    ///
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, error::KeyRejected> {
        // could refactor pkcs8::unwrap_key__(), ... later.
        let mut reader = untrusted::Reader::new(untrusted::Input::from(pkcs8));

        // take apart sequence first.
        let input2 = der::expect_tag_and_get_value(&mut reader, der::Tag::Sequence)
            .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
        let mut reader2 = untrusted::Reader::new(input2);

        // now look at the version number
        let actual_version = der::small_nonnegative_integer(&mut reader2)
            .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

        if actual_version > 1 {
            return Err(error::KeyRejected::version_not_supported());
        };

        let actual_alg_id = der::expect_tag_and_get_value(&mut reader2, der::Tag::Sequence)
            .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
        if let Some(alginfo) = signature::decode_possible_ecdsa(actual_alg_id) {
            let rng = rand::SystemRandom::new();
            let kp = EcdsaKeyPair::from_pkcs8(alginfo, pkcs8, &rng)?;
            return Ok(Self::EcdsaKeyPair(kp, &alginfo));
        } else {
            return Err(error::KeyRejected::unsupported_algorithm());
        };
    }

    /// Sign a message using a generic KeyPair.
    /// This calls the signing function from RSA, EcDSA or EdDSA modules.
    pub fn sign(&self,
                rng: &dyn rand::SecureRandom,
                message: &[u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        match self  {
            GenericKeyPair::EcdsaKeyPair(ekp, _) => {
                return ekp.sign(rng, message);
            }
            _ => { todo!("key {:?}", self); }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    //use crate::{signature, rand};

    #[test]
    fn test_load_ec_key() {
        const PRIVATE_KEY: &[u8] = include_bytes!("../tests/ecdsa_test_private_key_p256.p8");

        let pk = <GenericKeyPair>::from_pkcs8(PRIVATE_KEY);

        assert!(pk.is_ok());
    }

    #[test]
    fn test_load_pem_ec_key() {
        const PRIVATE_PEM: &[u8] = include_bytes!("../tests/ecdsa_test_private_key_p256.pem");

        let pk = <GenericKeyPair>::from_pkcs8_pem(PRIVATE_PEM);

        assert!(pk.is_ok());
    }

    #[test]
    fn test_sign_ec_key() {
        const PRIVATE_KEY: &[u8] = include_bytes!("../tests/ecdsa_test_private_key_p256.p8");

        let pk = <GenericKeyPair>::from_pkcs8(PRIVATE_KEY).unwrap();

        let message = [1,2,3,4,5,6,7,8];
        let rng = rand::SystemRandom::new();

        assert!(pk.sign(&rng, &message).is_ok());
    }
}
