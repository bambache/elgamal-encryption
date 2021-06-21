#[derive(Debug)]
pub struct PublicKey {
    pub p: String,
    pub g: String,
    pub h: String,
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
    pub p: String,
    pub g: String,
    pub x: String,
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

#[derive(Debug)]
pub struct Cipher {
    pub c1: String,
    pub c2: String,
}

impl Cipher {
    pub fn empty() -> Cipher {
        Cipher {
            c1: String::new(),
            c2: String::new(),
        }
    }
    pub fn new(c1: String, c2: String) -> Cipher {
        Cipher { c1: c1, c2: c2 }
    }
}
