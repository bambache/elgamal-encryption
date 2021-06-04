#[derive(Debug)]
pub struct PublicKey {
    p: String,
    g: String,
    h: String,
}

impl PublicKey {
    pub fn empty() -> PublicKey {
        PublicKey {
            p: String::new(),
            g: String::new(),
            h: String::new(),
        }
    }
    pub fn new(p: String, g: String, h: String) -> PublicKey {
        PublicKey { p: p, g: g, h: h }
    }
}

#[derive(Debug)]
pub struct PrivateKey {
    p: String,
    g: String,
    x: String,
}

impl PrivateKey {
    pub fn empty() -> PrivateKey {
        PrivateKey {
            p: String::new(),
            g: String::new(),
            x: String::new(),
        }
    }
    pub fn new(p: String, g: String, x: String) -> PrivateKey {
        PrivateKey { p: p, g: g, x: x }
    }
}

pub fn check(pair: (PublicKey, PrivateKey)) -> bool {
    let (public_key, private_key) = pair;

    public_key.p == private_key.p && public_key.g == private_key.g && public_key.h != private_key.x
}
