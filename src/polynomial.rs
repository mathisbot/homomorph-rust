use alloc::vec::Vec;

/// A polynomial over Z/2Z.
///
/// A polynomial is represented as a vector of coefficients.
/// For speed purposes, we store the coefficients in a vector of u128, representing 128 coefficients at a time.
///
/// ## WARNING
///
/// The first element of the vector are the terms with the least power of x
/// BUT bits are reversed because of u128, so the last bit of the first u128 is the constant term.
///
/// Thus, coefficient of x^i is stored in the (i/128)-th u128 at the (127-i%128)-th bit.
#[derive(Debug, PartialEq)]
pub struct Polynomial {
    coefficients: Vec<u128>,
    degree: usize,
}

impl Polynomial {
    pub fn new(coefficients: Vec<u128>) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        let degree = Self::compute_degree(&coefficients);
        Self {
            coefficients,
            degree,
        }
    }

    /// ## Safety
    ///
    /// The user must provide the correct degree
    pub unsafe fn new_unchecked(coefficients: Vec<u128>, degree: usize) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        Self {
            coefficients,
            degree,
        }
    }

    /// Compute the degree of a polynomial
    pub fn compute_degree(coefficients: &[u128]) -> usize {
        if let Some(i) = coefficients.iter().rposition(|&coeff| coeff != 0) {
            127 - coefficients[i].leading_zeros() as usize + 128 * i
        } else {
            0
        }
    }

    /// Generate a random polynomial of a given degree
    pub fn random(degree: usize) -> Self {
        let num_elements = (degree / 128) + 1;

        let mut coefficients: Vec<u128> = Vec::with_capacity(num_elements);
        unsafe {
            let bytes: &mut [u8] = core::slice::from_raw_parts_mut(
                coefficients.as_mut_ptr() as *mut u8,
                num_elements * core::mem::size_of::<u128>(),
            );
            getrandom::getrandom(bytes).expect("Failed to generate random bytes");
            coefficients.set_len(num_elements);
        }

        coefficients[num_elements - 1] &= (1 << (degree % 128)) - 1;
        coefficients[num_elements - 1] |= 1 << (degree % 128);

        unsafe { Self::new_unchecked(coefficients, degree) }
    }

    /// Returns the null polynomial
    ///
    /// ## Warning
    ///
    /// Although it is not mathematically correct, the null polynomial
    /// i considered to be of degree 0 in this implementation.
    pub fn null() -> Self {
        Self {
            coefficients: vec![0],
            degree: 0,
        }
    }

    /// Returns the monomial x^degree
    pub fn monomial(degree: usize) -> Self {
        let mut coefficients = vec![0; degree / 128 + 1];
        coefficients[degree / 128] = 1 << (degree % 128);

        unsafe { Self::new_unchecked(coefficients, degree) }
    }

    /// Evaluates the given polynomial at a given point
    pub fn evaluate(&self, x: bool) -> bool {
        if !x {
            return (self.coefficients[0] & 1) == 1;
        }

        let result = self
            .coefficients
            .iter()
            .fold(0, |acc, &coeff| acc + coeff.count_ones());

        (result % 2) == 1
    }

    pub fn degree(&self) -> usize {
        self.degree
    }

    pub fn coefficients(&self) -> &Vec<u128> {
        &self.coefficients
    }

    /// Add to polynomial together
    ///
    /// The reason this exists outside of the `std::ops::Add` trait is because
    /// it is interesting to add two polynomials without losing ownership of them.
    pub fn add(&self, other: &Self) -> Self {
        // We know that degree of the sum is at most max(deg(p1), deg(p2)).
        let max_deg = self.degree.max(other.degree);
        let mut result = Vec::with_capacity((max_deg + 127) / 128);

        for i in 0..self.coefficients.len().max(other.coefficients.len()) {
            result.push(
                self.coefficients.get(i).copied().unwrap_or(0)
                    ^ other.coefficients.get(i).copied().unwrap_or(0),
            );
        }

        if self.degree != other.degree {
            // We know that the degree of the sum is exactly max(deg(p1), deg(p2)).
            unsafe { Self::new_unchecked(result, max_deg) }
        } else {
            Self::new(result)
        }
    }

    /// Multiply to polynomial together
    ///
    /// The reason this exists outside of the `std::ops::Mul` trait is because
    /// it is interesting to add two polynomials without losing ownership of them.
    pub fn mul(&self, other: &Self) -> Self {
        // We need to handle the special case of the null polynomial
        // because the degree of the null polynomial is not well defined.
        if (self.degree == 0 && self.coefficients.first().copied().unwrap_or(0) == 0)
            || (other.degree == 0 && other.coefficients.first().copied().unwrap_or(0) == 0)
        {
            return Self::null();
        }

        // The degree of the product is deg(p1) + deg(p2).
        let result_len = (self.degree + other.degree) / 128 + 1;
        let mut result = vec![0; result_len];

        for (i, &a) in self.coefficients.iter().enumerate() {
            for (j, &b) in other.coefficients.iter().enumerate() {
                if i + j >= result_len {
                    break;
                }
                let mut shifted_a = a;
                for k in 0..128 {
                    if shifted_a & 1 != 0 {
                        result[i + j] ^= b << k;
                        if k > 0 && i + j + 1 < result_len {
                            result[i + j + 1] ^= b >> (128 - k);
                        }
                    }
                    shifted_a >>= 1;
                    if shifted_a == 0 {
                        break;
                    }
                }
            }
        }

        unsafe { Self::new_unchecked(result, self.degree + other.degree) }
    }

    /// Compute the remainder of the division of two polynomials
    pub fn rem(&self, other: &Self) -> Self {
        let mut r = self.clone().coefficients;
        let mut r_degree = self.degree;

        // At most self.degree - other.degree iterations
        while r_degree >= other.degree {
            let shift = r_degree - other.degree;
            let block_shift = shift / 128;
            let bit_shift = shift % 128;

            for i in 0..other.coefficients.len() {
                r[block_shift + i] ^= other.coefficients[i] << bit_shift;
                if bit_shift != 0 && block_shift + i + 1 < r.len() {
                    r[block_shift + i + 1] ^= other.coefficients[i] >> (128 - bit_shift);
                }
            }

            // Degree needs to be recomputed as it may not be
            // r_degree - 1
            r_degree = Self::compute_degree(&r);
        }

        unsafe { Polynomial::new_unchecked(r, r_degree) }
    }
}

impl Clone for Polynomial {
    fn clone(&self) -> Polynomial {
        let mut cloned_coefficients = Vec::with_capacity((self.degree + 127) / 128);
        for i in 0..=(self.degree / 128) {
            cloned_coefficients.push(self.coefficients[i]);
        }
        unsafe { Polynomial::new_unchecked(cloned_coefficients, self.degree) }
    }
}

#[cfg(test)]
mod test {
    use super::Polynomial;
    use alloc::vec::Vec;

    #[test]
    fn test_get_degree() {
        let coefficients = vec![0b10010];
        assert_eq!(Polynomial::compute_degree(&coefficients), 4);
    }

    #[test]
    fn test_new() {
        let p = Polynomial::new(vec![0b10010001]);
        assert_eq!(p.degree, 7);
    }

    #[test]
    #[should_panic]
    fn test_new_panic() {
        let _ = Polynomial::new(Vec::new());
    }

    #[test]
    fn test_new_unchecked() {
        unsafe {
            let _ = Polynomial::new_unchecked(vec![0b10010], 4);
        }
    }

    #[test]
    #[should_panic]
    fn test_new_unchecked_panic() {
        unsafe {
            let _ = Polynomial::new_unchecked(Vec::new(), 0);
        }
    }

    #[test]
    fn test_random() {
        let p = Polynomial::random(5);
        assert_eq!(Polynomial::compute_degree(&p.coefficients), 5);
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

        let p1 = Polynomial::new(vec![0b1001, 0b1000001101011010, 0b0, 0b1, 0b0]);
        let p2 = p1.clone();
        assert_eq!(p1.degree, p2.degree);
        // Assert that the coefficients are the same
        // (vectors may not be equal because of trailing zeros)
        for i in 0..p1.coefficients.len() {
            if i < p2.coefficients.len() && p1.coefficients[i] != p2.coefficients[i] {
                assert!(p1.coefficients[i..].iter().all(|&c| c == 0));
                break;
            }
        }
    }

    #[test]
    fn test_evaluate() {
        let p = Polynomial::new(vec![0b1001]);
        assert!(!p.evaluate(true));
        assert!(p.evaluate(false));

        let p = Polynomial::new(vec![0b111100010, 0b1001]);
        assert!(p.evaluate(true));
        assert!(!p.evaluate(false));
    }

    #[test]
    fn test_add_fn() {
        // Simple case
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b0011]);
        let p3 = p1.add(&p2);
        assert_eq!(p3.coefficients, vec![0b1010]);

        // Multiple coefficients
        let p1 = Polynomial::new(vec![0b1001, 0b1]);
        let p2 = Polynomial::new(vec![0b0101, 0b1]);
        let p3 = p1.add(&p2);
        assert_eq!(p3.coefficients, vec![0b1100, 0b0]);
    }

    #[test]
    fn test_mul_fn() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul(&p2);
        assert_eq!(p3.coefficients, vec![0b11011]);

        let p1 = Polynomial::new(vec![0b111]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul(&p2);
        assert_eq!(p3.coefficients, vec![0b1001]);

        let p1 = Polynomial::new(vec![u128::MAX]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul(&p2);
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
