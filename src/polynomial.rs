// A polynomial over Z/2Z.
// A polynomial is represented as a vector of coefficients.
// For speed purposes, we store the coefficients in a vector of u128, representing 128 coefficients at a time.
// WARNING: The first element of the vector are the terms with the least power of x.
// BUT bits are reversed because of u128, so the last bit of the first u128 is the constant term.
// Coefficients of x^i is stored in the (i/128)-th u128 at the (127-i%128)-th bit.
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

    // We trust the user to provide the correct degree.
    pub unsafe fn new_unchecked(coefficients: Vec<u128>, degree: usize) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        Self {
            coefficients,
            degree,
        }
    }

    fn compute_degree(coefficients: &[u128]) -> usize {
        for (i, &coeff) in coefficients.iter().enumerate().rev() {
            if coeff != 0 {
                return 127 - coeff.leading_zeros() as usize + 128 * i;
            }
        }
        0
    }

    pub fn random(degree: usize, rng: &mut impl rand::Rng) -> Self {
        let num_elements = degree / 128 + 1;

        let mut coefficients = Vec::with_capacity(num_elements);
        coefficients.extend((0..num_elements).map(|_| rng.gen::<u128>()));

        let bit_pos = degree % 128;
        coefficients[num_elements - 1] &= (1 << bit_pos) - 1;
        coefficients[num_elements - 1] |= 1 << bit_pos;

        unsafe { Self::new_unchecked(coefficients, degree) }
    }

    // It is not a problem to consider the null polynomial as a monomial of degree 0.
    // Although it is not mathematically correct.
    pub fn null() -> Self {
        Self {
            coefficients: vec![0],
            degree: 0,
        }
    }

    pub fn monomial(degree: usize) -> Self {
        let mut coefficients = vec![0; degree / 128 + 1];
        coefficients[degree / 128] = 1 << (degree % 128);

        unsafe { Self::new_unchecked(coefficients, degree) }
    }

    pub fn evaluate(&self, x: bool) -> bool {
        if x == false {
            return (self.coefficients[0] & 1) == 1;
        }

        let result = self
            .coefficients
            .iter()
            .fold(0, |acc, &coeff| acc + coeff.count_ones());

        (result % 2) == 1
    }

    pub fn _degree(&self) -> usize {
        self.degree
    }

    pub fn coefficients(&self) -> &Vec<u128> {
        &self.coefficients
    }

    pub fn add_fn(&self, other: &Self) -> Self {
        // We know that degree of the sum is at most max(deg(p1), deg(p2)).
        let max_deg = self.degree.max(other.degree);
        let mut result = Vec::with_capacity(max_deg / 128 + 1);

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

    pub fn mul_fn(&self, other: &Self) -> Self {
        // The degree of the product is deg(p1) + deg(p2).
        let sum_deg = self.degree + other.degree;
        let result_len = sum_deg / 128 + 1;
        let mut result = vec![0; result_len];

        for (i, &a) in self.coefficients.iter().enumerate() {
            for (j, &b) in other.coefficients.iter().enumerate() {
                if i + j >= result_len {
                    break;
                }
                let mut temp_a = a;
                let mut k = 0;
                while temp_a != 0 {
                    if temp_a & 1 != 0 {
                        if k < 128 {
                            result[i + j] ^= b << k;
                        }
                        if k > 0 && i + j + 1 < result_len {
                            result[i + j + 1] ^= b >> (128 - k);
                        }
                    }
                    temp_a >>= 1;
                    k += 1;
                }
            }
        }

        unsafe { Self::new_unchecked(result, sum_deg) }
    }

    pub fn rem(&self, other: &Self) -> Self {
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
                        r.coefficients[block_shift + i + 1] ^=
                            other.coefficients[i] >> (128 - bit_shift);
                    }
                }
            }

            r_degree = Self::compute_degree(&r.coefficients);
        }

        // Remove any leading zero coefficients
        // This is only useful for following processing
        while r.coefficients.len() > 1 && *r.coefficients.last().unwrap() == 0 {
            r.coefficients.pop();
        }

        r.degree = r_degree;

        r
    }
}

// Shortcut
impl Clone for Polynomial {
    fn clone(&self) -> Polynomial {
        let mut cloned_coefficients = Vec::with_capacity(self.degree / 128 + 1);
        for i in 0..=(self.degree / 128) {
            cloned_coefficients.push(self.coefficients[i]);
        }
        unsafe { Polynomial::new_unchecked(cloned_coefficients, self.degree) }
    }
}

#[cfg(test)]
mod test {
    use super::Polynomial;
    use rand;

    #[test]
    fn test_get_degree() {
        let coefficients = vec![0b10010];
        assert_eq!(Polynomial::compute_degree(&coefficients), 4);
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
        unsafe {
            let _ = Polynomial::new_unchecked(vec![0b10010], 4);
        }
    }

    #[test]
    #[should_panic]
    fn test_new_unchecked_panic() {
        unsafe {
            let _ = Polynomial::new_unchecked(vec![], 0);
        }
    }

    #[test]
    fn test_random() {
        let mut rng = rand::thread_rng();
        let p = Polynomial::random(5, &mut rng);
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
