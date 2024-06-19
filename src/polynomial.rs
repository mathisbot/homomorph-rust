use std::ops::{Add, Deref, Mul};

// A polynomial over Z/2Z.
// A polynomial is represented as a vector of coefficients.
// For speed purposes, we store the coefficients in a vector of u128, representing 128 coefficients at a time.
// WARNING: The first element of the vector are the terms with the least power of x.
// BUT bits are reversed because of u128, so the last bit of the first u128 is the constant term.
// Coefficients of x^i is stored in the (i/128)-th u128 at the (127-i%128)-th bit.
#[derive(Debug, PartialEq)]
pub struct Polynomial {
    coefficients: Vec<u128>,
    degree: usize, // The exact degree of the polynomial.
}

fn compute_degree(coefficients: &[u128]) -> usize {
    for i in (0..coefficients.len()).rev() {
        if coefficients[i] != 0 {
            return 127-coefficients[i].leading_zeros() as usize + 128*i;
        }
    }
    0
}

impl Polynomial {
    pub fn new(coefficients: Vec<u128>) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        let degree = compute_degree(&coefficients);
        Polynomial { coefficients, degree }
    }

    // We trust the user to provide the correct degree.
    pub unsafe fn new_unchecked(coefficients: Vec<u128>, degree: usize) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        Polynomial { coefficients, degree }
    }

    pub fn random(degree: usize, rng: &mut impl rand::Rng) -> Self {
        if degree == 0 {
            return Polynomial::null();
        }
        let mut coefficients = Vec::with_capacity(degree + 1);
        for _ in 0..(degree/128+1) {
            coefficients.push(rng.gen::<u128>());
        }
        // Overflow (underflow in this case) is a wanted behavior here.
        // #[allow(overflowing_literals)]
        coefficients[degree/128] &= (1 << (degree % 128)) - 1;
        coefficients[degree/128] |= 1 << (degree % 128);
        unsafe { Polynomial::new_unchecked(coefficients, degree) }
    }

    pub fn null() -> Self {
        Polynomial { coefficients: vec![0], degree: 0 }
    }

    pub fn monomial(degree: usize) -> Self {
        let mut coefficients = vec![0; degree/128 + 1];
        coefficients[degree/128] = 1 << (degree % 128);
        unsafe { Polynomial::new_unchecked(coefficients, degree) }
    }

    pub fn evaluate(&self, x: bool) -> bool {
        // Speed up
        if x == false {
            return (self.coefficients[0] & 1) == 1;
        }
        
        // Horners method
        let result = self.coefficients.iter()
            .rev()
            .fold(0, |acc, &coeff| acc + coeff.count_ones());
        
        (result % 2) == 1
    }

    pub(super) fn _degree(&self) -> usize {
        self.degree
    }
    
    pub(super) fn coefficients(&self) -> &Vec<u128> {
        &self.coefficients
    }

    pub fn add_fn(&self, other: &Polynomial) -> Polynomial {
        // We know that degree of the sum is at most max(deg(p1), deg(p2)).
        let max_deg = self.degree.max(other.degree);
        let mut result = Vec::with_capacity(max_deg/128 + 1);
        for i in 0..=(max_deg/128) {
            let mut coeff = 0;
            if i < self.coefficients.len() {
                coeff ^= self.coefficients[i];
            }
            if i < other.coefficients.len() {
                coeff ^= other.coefficients[i];
            }
            result.push(coeff);
        }

        if self.degree != other.degree {
            // We know that the degree of the sum is exactly max(deg(p1), deg(p2)).
            unsafe { Polynomial::new_unchecked(result, max_deg) }
        } else {
            Polynomial::new(result)
        }
    }

    pub fn mul_fn(&self, other: &Polynomial) -> Polynomial {
        // The degree of the product is deg(p1) + deg(p2).
        let sum_deg = self.degree + other.degree;
        let result_len = sum_deg/128 + 1;
        let mut result = vec![0; result_len];

        for (i, &a) in self.coefficients.iter().enumerate() {
            for (j, &b) in other.coefficients.iter().enumerate() {
                if i + j >= result.len() {
                    break;
                }
                let mut temp_a = a;
                let mut k = 0;
                while temp_a != 0 {
                    if temp_a & 1 != 0 {
                        if k < 128 {
                            result[i + j] ^= b << k;
                        }
                        if k > 0 && i + j + 1 < result.len() {
                            result[i + j + 1] ^= b >> (128 - k);
                        }
                    }
                    temp_a >>= 1;
                    k += 1;
                }
            }
        }

        unsafe { Polynomial::new_unchecked(result, sum_deg) }
    }

    // Barrett reduction
    // pub fn rem(&self, other: &Polynomial) -> Polynomial {
    //     use std::time::Instant;
    //     let start = Instant::now();
    //     let mut q = Polynomial::null();
    //     let mut r = self.clone();

    //     while r.degree >= other.degree {
    //         let shift = r.degree - other.degree;
    //         let mut q_term = vec![0; shift / 128 + 1];
    //         q_term[shift / 128] = 1 << (shift % 128);
    //         let q_poly = Polynomial::new(q_term);
    //         q = q.add_fn(&q_poly);
    //         r = r.add_fn(&other.mul_fn(&q_poly));
    //     }
    //     let end = start.elapsed();
    //     println!("Time needed to compute remind of {}/{} is {:?}", self.degree, other.degree, end);

    //     r
    // }

    pub fn rem(&self, other: &Polynomial) -> Polynomial {
        let mut r = self.clone();
        let mut r_degree = r.degree;
        let o_degree = other.degree;
        let o_len = other.coefficients.len();

        while r_degree >= o_degree {
            let shift = r_degree - o_degree;
            let block_shift = shift / 128;
            let bit_shift = shift % 128;

            // If bit_shift is zero, we just need to xor directly
            if bit_shift == 0 {
                for i in 0..o_len {
                    r.coefficients[block_shift + i] ^= other.coefficients[i];
                }
            } else {
                // When bit_shift is not zero, we need to handle the bit shifting
                for i in 0..o_len {
                    let other_shifted = other.coefficients[i] << bit_shift;
                    r.coefficients[block_shift + i] ^= other_shifted;
                    if block_shift + i + 1 < r.coefficients.len() {
                        r.coefficients[block_shift + i + 1] ^= other.coefficients[i] >> (128 - bit_shift);
                    }
                }
            }

            r_degree = compute_degree(&r.coefficients);
        }

        // Remove any leading zero coefficients
        while let Some(&last) = r.coefficients.last() {
            if last == 0 && r.coefficients.len() > 1 {
                r.coefficients.pop();
            } else {
                break;
            }
        }

        r.degree = r_degree;

        r
    }

    pub fn bit_and(&self, other: &Polynomial) -> Polynomial {
        self.mul_fn(other)
    }

    pub fn bit_xor(&self, other: &Polynomial) -> Polynomial {
        self.add_fn(other)
    }

    pub fn _bit_or(&self, other: &Polynomial) -> Polynomial {
        self.add_fn(other) + self.mul_fn(other)
    }
}

// Unlike add_fn, add takes ownership of the two polynomials.
impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, other: Polynomial) -> Polynomial {
        self.add_fn(&other)
    }
}

// Unlike mul_fn, mul takes ownership of the two polynomials.
impl Mul for Polynomial {
    type Output = Polynomial;

    fn mul(self, other: Polynomial) -> Polynomial {
        self.mul_fn(&other)
    }
}

// Shortcut
impl Clone for Polynomial {
    fn clone(&self) -> Polynomial {
        let mut cloned_coefficients = Vec::with_capacity(self.degree/128 + 1);
        for i in 0..=(self.degree/128) {
            cloned_coefficients.push(self.coefficients[i]);
        }
        unsafe { Polynomial::new_unchecked(cloned_coefficients, self.degree) }
    }
}

impl Deref for Polynomial {
    type Target = Vec<u128>;

    fn deref(&self) -> &Self::Target {
        &self.coefficients
    }
}


#[cfg(test)]
mod test {
    use crate::polynomial::compute_degree;

    use super::Polynomial;
    use rand;

    #[test]
    fn test_get_degree() {
        let coefficients = vec![0b10010];
        assert_eq!(super::compute_degree(&coefficients), 4);
    }

    #[test]
    fn test_new() {
        let p = Polynomial::new(vec![0b10010]);
        assert_eq!(p.degree, 4);
    }

    #[test]
    #[should_panic]
    fn test_new_panic() {
        let _ = Polynomial::new(vec![]);
    }

    #[test]
    fn test_new_unchecked() {
        unsafe { let _ = Polynomial::new_unchecked(vec![0b10010], 4); }
    }

    #[test]
    #[should_panic]
    fn test_new_unchecked_panic() {
        unsafe { let _ = Polynomial::new_unchecked(vec![], 0); }
    }

    #[test]
    fn test_random() {
        let mut rng = rand::thread_rng();
        let p = Polynomial::random(5, &mut rng);
        assert_eq!(compute_degree(&p.coefficients), 5);
    }

    #[test]
    fn test_null() {
        let p = Polynomial::null();
        assert_eq!(p.degree, 0);
        assert_eq!(p.coefficients, vec![0]);
    }

    #[test]
    fn test_clone() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = p1.clone();
        assert_eq!(p1.degree, p2.degree);
        assert_eq!(p1.coefficients, p2.coefficients);
    }

    #[test]
    fn test_evaluate() {
        let p = Polynomial::new(vec![0b1001]);
        assert_eq!(p.evaluate(true), false);
        assert_eq!(p.evaluate(false), true);

        let p = Polynomial::new(vec![0b111100010, 0b1001]);
        assert_eq!(p.evaluate(true), true);
        assert_eq!(p.evaluate(false), false);
    }

    #[test]
    fn test_add_fn() {
        // Simple case
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b0011]);
        let p3 = p1.add_fn(&p2);
        assert_eq!(p3.coefficients, vec![0b1010]);
        
        // Multiple coefficients
        let p1 = Polynomial::new(vec![0b1001, 0b1]);
        let p2 = Polynomial::new(vec![0b0101, 0b1]);
        let p3 = p1.add_fn(&p2);
        assert_eq!(p3.coefficients, vec![0b1100, 0b0]);
    }

    #[test]
    fn test_mul_fn() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul_fn(&p2);
        assert_eq!(p3.coefficients, vec![0b11011]);
        
        let p1 = Polynomial::new(vec![0b111]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul_fn(&p2);
        assert_eq!(p3.coefficients, vec![0b1001]);

        let p1 = Polynomial::new(vec![u128::MAX]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul_fn(&p2);
        assert_eq!(p3.coefficients, vec![0b1, 0b1]);
    }

    #[test]
    fn test_rem() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree < p2.degree);
        assert_eq!(p3.coefficients, vec![0]);
        
        let p1 = Polynomial::new(vec![0b1]);
        let p2 = Polynomial::new(vec![0b10]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree < p2.degree);
        assert_eq!(p3.coefficients, vec![0b1]);
        
        let p1 = Polynomial::new(vec![0b1010101101]);
        let p2 = Polynomial::new(vec![0b11011]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree < p2.degree);
        assert_eq!(p3.coefficients, vec![0b1010]);
    }
}