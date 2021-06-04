use elgamal_encryption::*;

#[test]
fn it_works() {
    let (public_key, private_key) = generate_keys(6).unwrap();
    println!("{:?}", public_key);
    println!("{:?}", private_key);
    assert_eq!(keys::check((public_key, private_key)), true);
}
