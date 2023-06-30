use crypto_hash;
use data_encoding;
use rand;

struct Unreserved;

impl Unreserved {
    fn new() -> Self {
        return Unreserved {};
    }

    fn get_octet_sequence(&self, len: u8) -> Vec<u8> {
        (0..len).map(|_| rand::random::<u8>()).collect::<Vec<_>>()
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
