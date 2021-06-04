use elgamal_encryption::*;
use elgamal_encryption::elgamal::*;

#[test]
fn it_works() {
    hello();
    hello_el();

    let mut public_key = PublicKey::new();
    let mut private_key = PrivateKey::new();
    generate_keys(6, &mut public_key, &mut private_key).unwrap();
    println!("{:?}", public_key);
    println!("{:?}", private_key);
}