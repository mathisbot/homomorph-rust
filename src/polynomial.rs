//! Polynomial backend for fast operations

use alloc::vec::Vec;

/// Represents a coefficient of a `Polynomial`.
pub(crate) type Coefficient = u128;

/// A polynomial over Z/2Z.
///
/// A polynomial is represented as a vector of coefficients.
/// For speed purposes, we store the coefficients in a vector of uint, representing multiple coefficients at a time.
///
/// ## WARNING
///
/// The first element of the vector are the terms with the least power of X
/// BUT bits are reversed because of binary representation, so the last bit of the first element is the constant term.
///
/// Thus, if x is Coefficient::BITS, coefficient of x^i is stored in the (i/x)-th usize at the (x-1-i%x)-th bit.
#[derive(Debug, Eq, zeroize::Zeroize)]
pub struct Polynomial {
    coefficients: Vec<Coefficient>,
    degree: usize,
}

impl Polynomial {
    /// Create a new polynomial from a vector of coefficients
    ///
    /// The degree of the polynomial is computed from the vector of coefficients.
    ///
    /// ## Panics
    ///
    /// If the vector of coefficients is empty.
    pub fn new(coefficients: Vec<Coefficient>) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        let degree = Self::compute_degree(&coefficients);
        Self {
            coefficients,
            degree,
        }
    }

    /// Create a new polynomial from a vector of coefficients and a degree
    ///
    /// ## Safety
    ///
    /// The user must provide the correct degree
    ///
    /// ## Panics
    ///
    /// If the vector of coefficients is empty.
    pub unsafe fn new_unchecked(coefficients: Vec<Coefficient>, degree: usize) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        Self {
            coefficients,
            degree,
        }
    }

    /// Compute the degree of a polynomial
    ///
    /// This function shouldn't be used outside of the crate as it is
    /// easier to get a polynomial's degree using the `degree` field.
    pub(crate) fn compute_degree(coefficients: &[Coefficient]) -> usize {
        if let Some(i) = coefficients.iter().rposition(|&coeff| coeff != 0) {
            Coefficient::BITS as usize - 1 - coefficients[i].leading_zeros() as usize
                + Coefficient::BITS as usize * i
        } else {
            0
        }
    }

    /// Generate a random polynomial of a given degree
    ///
    /// ## Note
    ///
    /// Randomness is generated using the `getrandom` crate.
    /// This means that randomness is cryptographically secure, and works on a vast majority
    /// of platforms, including baremetal (x86).
    pub fn random(degree: usize) -> Self {
        let num_elements = (degree / Coefficient::BITS as usize) + 1;

        let mut coefficients: Vec<Coefficient> = Vec::with_capacity(num_elements);

        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                coefficients.as_mut_ptr() as *mut u8,
                num_elements * size_of::<Coefficient>(),
            )
        };
        getrandom::getrandom(bytes).unwrap();
        unsafe { coefficients.set_len(num_elements) };

        coefficients[num_elements - 1] &= (1 << (degree % Coefficient::BITS as usize)) - 1;
        coefficients[num_elements - 1] |= 1 << (degree % Coefficient::BITS as usize);

        unsafe { Self::new_unchecked(coefficients, degree) }
    }

    /// Returns the null polynomial
    ///
    /// ## Warning
    ///
    /// Although it is not mathematically correct, the null polynomial
    /// is considered to be of degree 0 in this implementation.
    pub fn null() -> Self {
        Self {
            coefficients: vec![0],
            degree: 0,
        }
    }

    /// Returns the monomial x^degree
    pub fn monomial(degree: usize) -> Self {
        let mut coefficients = vec![0; degree / Coefficient::BITS as usize + 1];
        coefficients[degree / Coefficient::BITS as usize] =
            1 << (degree % Coefficient::BITS as usize);

        unsafe { Self::new_unchecked(coefficients, degree) }
    }

    /// Evaluates the given polynomial at a given point
    pub fn evaluate(&self, x: bool) -> bool {
        if !x {
            return (self.coefficients()[0] & 1) == 1;
        }

        let result = self
            .coefficients()
            .iter()
            .fold(0, |acc, &coeff| acc + coeff.count_ones());

        (result % 2) == 1
    }

    /// Returns the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the coefficients of the polynomial
    pub fn coefficients(&self) -> &Vec<Coefficient> {
        &self.coefficients
    }

    /// Add two polynomials together
    ///
    /// The reason this function exists outside of the `std::ops::Add` trait is because
    /// it is interesting to add two polynomials without losing ownership of them.
    ///
    /// However, this function allocates a new polynomial.
    pub fn add(&self, other: &Self) -> Self {
        // We know that degree of the sum is at most max(deg(p1), deg(p2)).
        let max_deg = self.degree().max(other.degree());
        let len = max_deg / Coefficient::BITS as usize + 1;
        let mut result = Vec::with_capacity(len);

        for i in 0..len {
            result.push(
                self.coefficients().get(i).copied().unwrap_or(0)
                    ^ other.coefficients().get(i).copied().unwrap_or(0),
            );
        }

        if self.degree() != other.degree() {
            // We know that the degree of the sum is exactly max(deg(p1), deg(p2)).
            unsafe { Self::new_unchecked(result, max_deg) }
        } else {
            Self::new(result)
        }
    }

    /// Multiply two polynomials together
    ///
    /// The reason this function exists outside of the `std::ops::Mul` trait is because
    /// it is interesting to add two polynomials without losing ownership of them.
    ///
    /// However, this function allocates a new polynomial.
    pub fn mul(&self, other: &Self) -> Self {
        // We need to handle the special case of the null polynomial
        // because the degree of the null polynomial is not well defined.
        if (self.degree() == 0 && self.coefficients().first().copied().unwrap_or(0) == 0)
            || (other.degree() == 0 && other.coefficients().first().copied().unwrap_or(0) == 0)
        {
            return Self::null();
        }

        // The degree of the product is deg(p1) + deg(p2).
        let result_len = (self.degree() + other.degree()) / Coefficient::BITS as usize + 1;
        let mut result = vec![0; result_len];

        for (i, &a) in self
            .coefficients()
            .iter()
            .take(self.degree() / Coefficient::BITS as usize + 1)
            .enumerate()
        {
            for (j, &b) in other
                .coefficients()
                .iter()
                .take(other.degree() / Coefficient::BITS as usize + 1)
                .enumerate()
            {
                let mut shifted_a = a;

                // This inner loop shows that polynomial multiplication doesn't
                // really benefit from using uints instead of `bool`s.
                // TODO: Think hard and find a way to optimize this.
                for k in 0..Coefficient::BITS as usize {
                    if shifted_a & 1 == 1 {
                        result[i + j] ^= b << k;
                        if k > 0 && i + j + 1 < result_len {
                            result[i + j + 1] ^= b >> (Coefficient::BITS as usize - k);
                        }
                    }
                    shifted_a >>= 1;
                    if shifted_a == 0 {
                        break;
                    }
                }
            }
        }

        unsafe { Self::new_unchecked(result, self.degree() + other.degree()) }
    }

    /// Compute the remainder of the division of two polynomials
    ///
    /// This function allocates a new polynomial.
    pub fn rem(&self, other: &Self) -> Self {
        let mut r = self.coefficients().clone();
        let mut r_degree = self.degree();

        let max_coefficient_idx =
            (other.degree() / Coefficient::BITS as usize + 1).min(other.coefficients().len());

        // At most self.degree() - other.degree() iterations
        while r_degree >= other.degree() {
            let shift = r_degree - other.degree();
            let block_shift = shift / Coefficient::BITS as usize;
            let bit_shift = shift % Coefficient::BITS as usize;

            for i in 0..max_coefficient_idx {
                r[block_shift + i] ^= other.coefficients()[i] << bit_shift;
                if bit_shift != 0 && block_shift + i + 1 < r.len() {
                    r[block_shift + i + 1] ^=
                        other.coefficients()[i] >> (Coefficient::BITS as usize - bit_shift);
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
        let mut cloned_coefficients = Vec::with_capacity(
            (self.degree() + Coefficient::BITS as usize - 1) / Coefficient::BITS as usize,
        );
        for i in 0..=(self.degree() / Coefficient::BITS as usize) {
            cloned_coefficients.push(self.coefficients()[i]);
        }
        unsafe { Polynomial::new_unchecked(cloned_coefficients, self.degree()) }
    }
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        self.degree() == other.degree()
            && self.coefficients()[0..self.degree() / Coefficient::BITS as usize + 1]
                == other.coefficients()[0..other.degree() / Coefficient::BITS as usize + 1]
    }
}

#[cfg(test)]
mod test {
    use super::{Coefficient, Polynomial};

    #[test]
    fn test_compute_degree() {
        let coefficients = vec![0b10010];
        assert_eq!(Polynomial::compute_degree(&coefficients), 4);

        let coefficients = vec![0b10010, 0b1];
        assert_eq!(
            Polynomial::compute_degree(&coefficients),
            Coefficient::BITS as usize
        );

        let coefficients = vec![0b10010, 0b0];
        assert_eq!(Polynomial::compute_degree(&coefficients), 4);
    }

    #[test]
    fn test_random() {
        let p = Polynomial::random(5);
        assert_eq!(Polynomial::compute_degree(p.coefficients()), 5);

        let p = Polynomial::random(Coefficient::BITS as usize);
        assert_eq!(
            Polynomial::compute_degree(p.coefficients()),
            Coefficient::BITS as usize
        );
    }

    #[test]
    fn test_clone() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = p1.clone();
        assert_eq!(p1, p2);

        let p1 = Polynomial::new(vec![0b1001, 0b1000001101011010, 0b0, 0b1, 0b0]);
        let p2 = p1.clone();
        assert_eq!(p1, p2);
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
        assert_eq!(*p3.coefficients(), vec![0b1010]);

        // Multiple coefficients
        let p1 = Polynomial::new(vec![0b1001, 0b1]);
        let p2 = Polynomial::new(vec![0b0101, 0b1]);
        let p3 = p1.add(&p2);
        assert_eq!(*p3.coefficients(), vec![0b1100, 0b0]);
    }

    #[test]
    fn test_mul_fn() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul(&p2);
        assert_eq!(*p3.coefficients(), vec![0b11011]);

        let p1 = Polynomial::new(vec![0b111]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul(&p2);
        assert_eq!(*p3.coefficients(), vec![0b1001]);

        let p1 = Polynomial::new(vec![Coefficient::MAX]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.mul(&p2);
        assert_eq!(*p3.coefficients(), vec![0b1, 0b1]);
    }

    #[test]
    fn test_rem() {
        let p1 = Polynomial::new(vec![0b1001]);
        let p2 = Polynomial::new(vec![0b11]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree() < p2.degree());
        assert_eq!(*p3.coefficients(), vec![0]);

        let p1 = Polynomial::new(vec![0b1]);
        let p2 = Polynomial::new(vec![0b10]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree() < p2.degree());
        assert_eq!(*p3.coefficients(), vec![1]);

        let p1 = Polynomial::new(vec![0b1010101101]);
        let p2 = Polynomial::new(vec![0b11011]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree() < p2.degree());
        assert_eq!(*p3.coefficients(), vec![0b1010]);
    }
}
