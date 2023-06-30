use crypto_hash;
use data_encoding;
use rand;

const UNRESERVED: [u8; 66] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2D, 0x2E,
    0x5f, 0x7E,
];

struct Unreserved(&'static [u8; 66]);

impl Unreserved {
    fn new() -> Self {
        return Unreserved(&UNRESERVED);
    }

    fn get_octet_sequence(&self, len: u8) -> Vec<u8> {
        (0..len)
            .map(|_| rand::random::<u8>())
            .map(|r| r as usize % self.0.len())
            .map(|r| self.0[r])
            .collect::<Vec<_>>()
    }
}

pub enum ChallengMethod {
    Plain,
    Sha256,
}

pub struct CodeVerifier(String);

impl CodeVerifier {
    pub fn new() -> Self {
        let unreserved = Unreserved::new();
        let octet_seq = unreserved.get_octet_sequence(32);
        let encoded = data_encoding::BASE64URL.encode(&octet_seq);
        return Self(encoded);
    }

    pub fn get_code_verifier(&self) -> String {
        self.0.clone()
    }

    pub fn get_code_challange(&self, challenge_method: ChallengMethod) -> String {
        match challenge_method {
            ChallengMethod::Plain => self.0.clone(),
            ChallengMethod::Sha256 => {
                let hash = crypto_hash::digest(crypto_hash::Algorithm::SHA256, &self.0.as_bytes());
                let encoded = data_encoding::BASE64URL.encode(&hash);
                encoded
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_octect_sequence() {
        let unreserved = Unreserved::new();
        let res = unreserved.get_octet_sequence(43);
        res.iter().for_each(|c| print!("{}", c));
        println!("");
        // assert!(false);
        res.iter().for_each(|v| assert!(UNRESERVED.contains(v)));
    }

    #[test]
    fn test_get_code_verifier() {
        let verifier = CodeVerifier::new();
        let code_verifier = verifier.get_code_verifier();
        println!("{code_verifier}");
        assert_eq!(code_verifier.len(), 44);
    }

    #[test]
    fn test_get_code_challenge_plain() {
        let verifier = CodeVerifier::new();
        let challenge = verifier.get_code_challange(ChallengMethod::Plain);
        println!("{challenge}");
    }

    #[test]
    fn test_get_code_challenge_sha256() {
        let verifier = CodeVerifier::new();
        let challenge = verifier.get_code_challange(ChallengMethod::Sha256);
        println!("{challenge}");
    }
}
