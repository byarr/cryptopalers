use crate::block::{aes_128_ecb_decrypt, aes_128_ecb_encrypt};
use std::collections::HashMap;

fn cookie_parse(s: &str) -> HashMap<String, String> {
    let parts: Vec<_> = s.split(|c: char| c == '=' || c == '&').collect();

    let mut result = HashMap::new();
    for i in 0..(parts.len() / 2) {
        result.insert(parts[i * 2].to_string(), parts[i * 2 + 1].to_string());
    }

    result
}

fn profile_for(email: &str) -> Result<String, char> {
    if email.contains('&') {
        Err('&')
    } else if email.contains('=') {
        Err('=')
    } else {
        Ok(format!("email={email}&uid=10&role=user"))
    }
}

struct ProfileOracle {
    key: [u8; 16],
}

impl ProfileOracle {
    fn new() -> Self {
        let key = [0u8; 16];
        ProfileOracle { key }
    }

    fn enc_profile_for(&self, email: &str) -> Vec<u8> {
        let profile = profile_for(email).unwrap();

        aes_128_ecb_encrypt(&self.key, profile.into_bytes())
    }

    fn is_admin_profile(&self, data: &[u8]) -> bool {
        let decrypt = aes_128_ecb_decrypt(&self.key, data);

        let profile_cookie = String::from_utf8(decrypt).unwrap();

        let profile = cookie_parse(&profile_cookie);
        profile.get("role").map(|r| r == "admin").unwrap_or(false)
    }
}

fn generate_admin_profile(oracle: &ProfileOracle) -> Vec<u8> {
    // email=X&uid=10&role= user

    // | email=1234567890 | 123&uid=10&role= | user
    // 13 char email address gives us role= by itself
    let ending_role = oracle.enc_profile_for("foo@haxor.com");

    // now trick it into encoding padded(admin) in the middle of the email e.g.
    // | email=1234567890 | admin\x0b\xob ... | 123&uid=10&role= | user

    let admin_email = "123456789@admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b.com";
    let admin_email_role = oracle.enc_profile_for(admin_email);

    let mut result = Vec::new();
    result.extend_from_slice(&ending_role[0..32]);
    result.extend_from_slice(&admin_email_role[16..32]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_parse() {
        let mut expected = HashMap::new();
        expected.insert("foo".to_string(), "bar".to_string());
        expected.insert("baz".to_string(), "qux".to_string());
        expected.insert("zap".to_string(), "zazzle".to_string());

        assert_eq!(cookie_parse("foo=bar&baz=qux&zap=zazzle"), expected);
    }

    #[test]
    fn test_profile_for_parse() {
        let profile_cookie = profile_for("foo@bar.com").unwrap();
        let mut expected = HashMap::new();
        expected.insert("email".to_string(), "foo@bar.com".to_string());
        expected.insert("uid".to_string(), "10".to_string());
        expected.insert("role".to_string(), "user".to_string());

        assert_eq!(cookie_parse(&profile_cookie), expected);
    }

    #[test]
    fn test_generate_admin_profile() {
        let oracle = ProfileOracle::new();
        let admin_profile = generate_admin_profile(&oracle);
        assert!(oracle.is_admin_profile(&admin_profile));
    }
}
