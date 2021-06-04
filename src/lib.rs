pub mod elgamal;

pub fn hello() {
    println!("Lib hello");
    elgamal::hello_el();
    // let p = elgamal::generate_prime(8, true);
    // if p.is_ok() {
    //     println!("prime is {}",p.ok().unwrap());
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works_2() {
        hello();
        assert_eq!(2 + 2, 4);
        // let p = elgamal::generate_prime(6, true);

        // assert_eq!(p?, 59);
    }
}
