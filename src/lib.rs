use rand::prelude::*;
use sha3::{Digest, Sha3_512};
use std::error::Error;

const NONCE_LEN: usize = 2;

pub trait LigmaAlgorithm {
    type PublicKey;
    type PrivateKey;
    type Signature;
    type Message;

    fn generate_keypair() -> Result<(Self::PublicKey, Self::PrivateKey), Box<dyn Error>>;
    fn sign(
        message: &Self::Message,
        private_key: &Self::PrivateKey,
    ) -> Result<Self::Signature, Box<dyn Error>>;
    fn verify(
        message: &Self::Message,
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> Result<bool, Box<dyn Error>>;
}

#[derive(Clone, Debug)]
pub struct LigmaSafetyOptions {
    /// increases algorithm complexity. 1024 for Paranoid level
    pub lattice_dimension: usize,
    /// very large prime number. 33554393 for Paranoid level
    pub modulus: i128,
    /// can type anything
    pub security_level: SecurityLevel,
}

#[derive(Clone, Debug)]
pub enum SecurityLevel {
    Basic,    // NIST Level 1 equivalent (128-bit classical security)
    Standard, // NIST Level 3 equivalent (192-bit classical security)
    Paranoid, // NIST Level 5 equivalent (256-bit classical security)
}

impl SecurityLevel {
    fn get_parameters(&self) -> LigmaSafetyOptions {
        match self {
            SecurityLevel::Basic => LigmaSafetyOptions {
                lattice_dimension: 512,
                modulus: 8380417,
                security_level: SecurityLevel::Basic,
            },
            SecurityLevel::Standard => LigmaSafetyOptions {
                lattice_dimension: 768,
                modulus: 16760833,
                security_level: SecurityLevel::Standard,
            },
            SecurityLevel::Paranoid => LigmaSafetyOptions {
                lattice_dimension: 1024,
                modulus: 33554393,
                security_level: SecurityLevel::Paranoid,
            },
        }
    }
}

impl Default for LigmaSafetyOptions {
    fn default() -> Self {
        SecurityLevel::Standard.get_parameters()
    }
}

#[derive(Clone, Debug)]
pub struct LatticePublicKey {
    pub matrix_a: Vec<Vec<i128>>,
    pub vector_b: Vec<i128>,
}

#[derive(Clone, Debug)]
pub struct LatticePrivateKey {
    pub secret_key: Vec<i128>,
}

pub struct LigmaSafety {
    options: LigmaSafetyOptions,
}

impl LigmaSafety {
    pub fn new(options: LigmaSafetyOptions) -> Self {
        Self { options }
    }

    pub fn with_security_level(level: SecurityLevel) -> Self {
        Self {
            options: level.get_parameters(),
        }
    }

    pub fn generate_keypair(
        &self,
    ) -> Result<(LatticePublicKey, LatticePrivateKey), Box<dyn Error>> {
        let mut rng = rand::rng();

        let secret_key: Vec<i128> = (0..self.options.lattice_dimension)
            .map(|_| rng.random_range(-1..=1))
            .collect();

        let matrix_a = self.generate_matrix(&mut rng)?;
        let vector_b = self.matrix_vector_mul(&matrix_a, &secret_key)?;

        Ok((
            LatticePublicKey { matrix_a, vector_b },
            LatticePrivateKey { secret_key },
        ))
    }

    fn generate_matrix(&self, rng: &mut impl Rng) -> Result<Vec<Vec<i128>>, Box<dyn Error>> {
        let dim = self.options.lattice_dimension;
        let modulus = self.options.modulus;
        Ok((0..dim)
            .map(|_| (0..dim).map(|_| rng.random_range(0..modulus)).collect())
            .collect())
    }

    pub fn sign(
        &self,
        message: &[u8],
        private_key: &LatticePrivateKey,
    ) -> Result<Vec<i128>, Box<dyn Error>> {
        let mut rng = rand::rng();
        let mut nonce = Vec::with_capacity(NONCE_LEN);
        for _ in 0..NONCE_LEN {
            let value = rng.random_range(0..self.options.modulus);
            nonce.push(value);
        }

        let mut nonce_bytes = Vec::with_capacity(NONCE_LEN * 4);
        for n in &nonce {
            nonce_bytes.extend_from_slice(&n.to_le_bytes());
        }
        let hash_scalar = self.hash_message_with_nonce(&nonce_bytes, message)?;

        let mut sig_body = vec![0; self.options.lattice_dimension];
        for i in 0..self.options.lattice_dimension {
            sig_body[i] = self.mod_mul(private_key.secret_key[i], hash_scalar);
        }

        let mut signature = nonce;
        signature.extend(sig_body);
        Ok(signature)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[i128],
        public_key: &LatticePublicKey,
    ) -> Result<bool, Box<dyn Error>> {
        if signature.len() != NONCE_LEN + self.options.lattice_dimension {
            return Ok(false);
        }

        let nonce = &signature[0..NONCE_LEN];
        let mut nonce_bytes = Vec::with_capacity(NONCE_LEN * 4);
        for n in nonce {
            nonce_bytes.extend_from_slice(&n.to_le_bytes());
        }
        let hash_scalar = self.hash_message_with_nonce(&nonce_bytes, message)?;

        let sig_body = &signature[NONCE_LEN..];

        let actual = self.matrix_vector_mul(&public_key.matrix_a, sig_body)?;
        let expected: Vec<i128> = public_key
            .vector_b
            .iter()
            .map(|&b_i| self.mod_mul(b_i, hash_scalar))
            .collect();

        for i in 0..self.options.lattice_dimension {
            if self.mod_norm(self.mod_sub(actual[i], expected[i])) != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn hash_message_with_nonce(
        &self,
        nonce_bytes: &[u8],
        message: &[u8],
    ) -> Result<i128, Box<dyn Error>> {
        let mut hasher = Sha3_512::new();
        hasher.update(nonce_bytes);
        hasher.update(message);
        let hash = hasher.finalize();
        let sum: i128 = hash.iter().map(|&b| b as i128).sum();
        let scalar = (sum % (self.options.modulus - 1)) + 1;
        Ok(scalar)
    }

    fn matrix_vector_mul(
        &self,
        matrix: &[Vec<i128>],
        vector: &[i128],
    ) -> Result<Vec<i128>, Box<dyn Error>> {
        let mut result = vec![0; self.options.lattice_dimension];
        for i in 0..self.options.lattice_dimension {
            for j in 0..self.options.lattice_dimension {
                result[i] = self.mod_add(result[i], self.mod_mul(matrix[i][j], vector[j]));
            }
        }
        Ok(result)
    }

    fn mod_norm(&self, a: i128) -> i128 {
        let m = self.options.modulus;
        let r = a % m;
        if r < 0 {
            r + m
        } else {
            r
        }
    }

    fn mod_add(&self, a: i128, b: i128) -> i128 {
        self.mod_norm(a + b)
    }

    fn mod_mul(&self, a: i128, b: i128) -> i128 {
        self.mod_norm(a * b)
    }

    fn mod_sub(&self, a: i128, b: i128) -> i128 {
        self.mod_norm(a - b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_different_messages() {
        let ligma = LigmaSafety::with_security_level(SecurityLevel::Basic);
        let (public_key, private_key) = ligma.generate_keypair().unwrap();

        let message1 = b"ligma balls";
        let message2 = b"keanu Reeves";

        let signature = ligma.sign(message1, &private_key).unwrap();
        let is_valid_wrong = ligma.verify(message2, &signature, &public_key).unwrap();
        assert!(!is_valid_wrong, "different messages should not verify");

        let is_valid_correct = ligma.verify(message1, &signature, &public_key).unwrap();
        assert!(is_valid_correct, "original message should verify");
    }

    #[test]
    fn test_verification_sensitivity() {
        let ligma = LigmaSafety::with_security_level(SecurityLevel::Basic);
        let (public_key, private_key) = ligma.generate_keypair().unwrap();

        let base_message = b"ligma balls";
        let signature = ligma.sign(base_message, &private_key).unwrap();

        for i in 0..base_message.len() {
            let mut modified = base_message.to_vec();
            modified[i] = modified[i].wrapping_add(1);
            let is_valid = ligma.verify(&modified, &signature, &public_key).unwrap();
            assert!(
                !is_valid,
                "modified message at position {} should not verify",
                i
            );
        }
    }

    #[test]
    fn test_bit_sensitivity() {
        let ligma = LigmaSafety::with_security_level(SecurityLevel::Basic);
        let (public_key, private_key) = ligma.generate_keypair().unwrap();
        let message = b"ligma balls";
        let signature = ligma.sign(message, &private_key).unwrap();

        for i in 0..signature.len() {
            let mut modified_signature = signature.clone();
            modified_signature[i] = modified_signature[i] ^ 1;

            let is_valid = ligma
                .verify(message, &modified_signature, &public_key)
                .unwrap();
            assert!(!is_valid, "modified signature should not verify");
        }
    }

    #[test]
    fn test_length_extension_resistance() {
        let ligma = LigmaSafety::with_security_level(SecurityLevel::Standard);
        let (public_key, private_key) = ligma.generate_keypair().unwrap();

        let message1 = b"steve jobs";
        let message2 = b"steve jobs ligma balls";

        let signature1 = ligma.sign(message1, &private_key).unwrap();
        let is_valid = ligma.verify(message2, &signature1, &public_key).unwrap();

        assert!(!is_valid, "length extension should not be possible");
    }

    #[test]

    fn test_performance_characteristics() {
        use std::time::Instant;

        let ligma = LigmaSafety::with_security_level(SecurityLevel::Paranoid);
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus error sit voluptatem.";

        let start = Instant::now();
        let (public_key, private_key) = ligma.generate_keypair().unwrap();
        let keygen_time = start.elapsed();

        let start = Instant::now();
        let signature = ligma.sign(message, &private_key).unwrap();
        let sign_time = start.elapsed();

        let start = Instant::now();
        let _ = ligma.verify(message, &signature, &public_key).unwrap();
        let verify_time = start.elapsed();

        println!("Key generation time: {:?}", keygen_time);
        println!("Signing time: {:?}", sign_time);
        println!("Verification time: {:?}", verify_time);
    }
}
