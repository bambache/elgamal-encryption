pub mod keys;

use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::error::ErrorStack;
use std::cmp::Ordering;

const MIN_BITS: i32 = 6;
const MAX_BITS: i32 = 1024;

type Result<T> = std::result::Result<T, ElgamalError>;

#[derive(Debug, Clone)]
pub enum ElgamalError {
    InvalidArgument,
    Parse(ErrorStack),
}

// Implement the conversion from `ErrorStack` to `ElgamalError`.
// This will be automatically called by `?` if a `ErrorStack`
// needs to be converted into a `ElgamalError`.
impl From<ErrorStack> for ElgamalError {
    fn from(err: ErrorStack) -> ElgamalError {
        ElgamalError::Parse(err)
    }
}

fn find_primitive_root_mod_exp(p: &BigNum) -> Result<BigNum> {
    let one = BigNum::from_u32(1)?;
    let two = BigNum::from_u32(2)?;
    let mut ctx = BigNumContext::new()?;
    let mut result = BigNum::new()?;

    if p.cmp(&two) == Ordering::Equal {
        result.mod_exp(&p, &two, &p, &mut ctx)?;
        return Ok(result);
    }

    // the prime divisors of p-1 are 2 and (p-1)/2 because
    // p = 2x + 1 where x is a prime
    let p_1 = p - &one;

    // p1 = 2
    // p2 = (p-1) // p1
    let p2 = &p_1 / &two;
    let p_2 = p - &two;

    loop {
        // g = random , 2 <= g <= p - 1
        // we use first 0 <= g < p - 2, then add 2 to obtain the above
        let mut g = BigNum::new()?;
        p_2.rand_range(&mut g)?;
        g = &g + &two;

        // g is a primitive root if for all prime factors of p-1, p[i]
        // g^((p-1)/p[i]) (mod p) is not congruent to 1
        // 	if not (modexp( g, (p-1)//p1, p ) == 1):
        let mut r = BigNum::new()?;
        r.mod_exp(&g, &p2, p, &mut ctx)?;

        if r.cmp(&one) != Ordering::Equal {
            // r != 1
            // if not modexp( g, (p-1)//p2, p ) == 1:
            //   return g
            r.mod_exp(&g, &two, p, &mut ctx)?;
            if r.cmp(&one) != Ordering::Equal {
                // r != 1
                result.mod_exp(&g, &two, &p, &mut ctx)?;
                return Ok(result);
            }
        }
    }
}

pub fn generate_keys(bits: i32) -> Result<(keys::PublicKey, keys::PrivateKey)> {
    if bits < MIN_BITS || bits > MAX_BITS {
        return Err(ElgamalError::InvalidArgument);
    }

    // p is the prime (safe prime)
    let mut p = BigNum::new()?;
    p.generate_prime(bits, true, None, None)?;

    let two = BigNum::from_u32(2)?;
    let g = find_primitive_root_mod_exp(&p)?;

    let p_2 = &p - &two;

    // x is random in (0, p-1)
    // we use first 0 <= x < p - 2, then add 1 to obtain the above
    let mut x = BigNum::new()?;
    p_2.rand_range(&mut x)?;
    x = &x + &two;

    // h = g ^ x mod p
    // h = modexp( g, x, p )
    let mut ctx = BigNumContext::new()?;
    let mut h = BigNum::new()?;
    h.mod_exp(&g, &x, &p, &mut ctx)?;

    Ok((
        keys::PublicKey::new(
            p.to_dec_str()?.to_string(),
            g.to_dec_str()?.to_string(),
            h.to_dec_str()?.to_string(),
        ),
        keys::PrivateKey::new(
            p.to_dec_str()?.to_string(),
            g.to_dec_str()?.to_string(),
            x.to_dec_str()?.to_string(),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works_2() {
        let (public_key, private_key) = generate_keys(6).unwrap();
        println!("{:?}", public_key);
        println!("{:?}", private_key);
        assert_eq!(keys::check((public_key, private_key)), true);
    }
}
