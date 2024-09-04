//! Polynomial backend for fast operations on polynomials over Z/2Z.

use alloc::boxed::Box;
use alloc::vec::Vec;

/// Represents a coefficient of a `Polynomial`.
type Coefficient = usize;

const BITS_PER_COEFF: usize = Coefficient::BITS as usize;

/// A polynomial over Z/2Z.
///
/// A polynomial is represented as a list of coefficients.
/// For speed purposes, we store the coefficients in a boxed slice of uint, representing multiple coefficients at a time.
///
/// ## WARNING
///
/// The first element of the vector are the terms with the least power of X
/// BUT bits are reversed because of binary representation, so the last bit of the first element is the constant term.
///
/// Thus, if we note b the value `Coefficient::BITS`, coefficient of X^i is the (b-1-i%b)-th bit of the (i/b)-th usize.
#[derive(Debug, Eq)]
pub struct Polynomial {
    coefficients: Box<[Coefficient]>,
    degree: usize,
}

impl Polynomial {
    /// Compute the degree of a polynomial
    ///
    /// This function shouldn't be used outside of the crate as it is
    /// easier to get a polynomial's degree using the `degree` field.
    fn compute_degree(coefficients: &[Coefficient]) -> usize {
        coefficients
            .iter()
            .rposition(|&coeff| coeff != 0)
            .map_or(0, |i| {
                BITS_PER_COEFF - 1 - coefficients[i].leading_zeros() as usize + BITS_PER_COEFF * i
            })
    }

    /// Create a new polynomial from a boxed slice of coefficients
    ///
    /// The degree of the polynomial is computed from the vector of coefficients.
    ///
    /// ## Panics
    ///
    /// If the vector of coefficients is empty.
    pub fn new(coefficients: Box<[Coefficient]>) -> Self {
        assert!(
            !coefficients.is_empty(),
            "The vector of coefficients must not be empty."
        );
        let degree = Self::compute_degree(&coefficients);
        Self {
            coefficients,
            degree,
        }
    }

    /// Create a new polynomial of degree 0 from a bool
    pub fn new_from_bool(x: bool) -> Self {
        let coefficients = Box::new([Coefficient::from(x)]);
        Self {
            coefficients,
            degree: 0,
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
        let num_elements = (degree / BITS_PER_COEFF) + 1;

        let mut coefficients = vec![0; num_elements].into_boxed_slice();

        // Safety
        // `vec!` ensures that the buffer is big enough to hold `num_elements` elements,
        // therefore `num_elements * size_of::<Coefficient>()` bytes.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                coefficients.as_mut_ptr().cast::<u8>(),
                num_elements * size_of::<Coefficient>(),
            )
        };
        getrandom::getrandom(bytes).unwrap();

        coefficients[num_elements - 1] &= (1 << (degree % BITS_PER_COEFF)) - 1;
        coefficients[num_elements - 1] |= 1 << (degree % BITS_PER_COEFF);

        Self {
            coefficients,
            degree,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.coefficients.len() * size_of::<Coefficient>());
        for &coeff in self.coefficients() {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(!bytes.is_empty(), "The vector of bytes must not be empty.");
        let mut coefficients =
            vec![0; (bytes.len() + size_of::<Coefficient>() - 1) / size_of::<Coefficient>()]
                .into_boxed_slice();
        for (i, chunk) in bytes.chunks(size_of::<Coefficient>()).enumerate() {
            let mut coeff_bytes = [0; size_of::<Coefficient>()];
            coeff_bytes[..chunk.len()].copy_from_slice(chunk);
            coefficients[i] = Coefficient::from_le_bytes(coeff_bytes);
        }
        let degree = Self::compute_degree(&coefficients);
        Self {
            coefficients,
            degree,
        }
    }

    /// Returns the null polynomial
    ///
    /// ## Warning
    ///
    /// Although it is not mathematically correct, the null polynomial
    /// is considered to be of degree 0 in this implementation.
    pub fn null() -> Self {
        Self {
            coefficients: Box::new([0]),
            degree: 0,
        }
    }

    /// Returns the monomial x^degree
    pub fn monomial(degree: usize) -> Self {
        let mut coefficients = vec![0; degree / BITS_PER_COEFF + 1].into_boxed_slice();
        coefficients[degree / BITS_PER_COEFF] = 1 << (degree % BITS_PER_COEFF);

        Self {
            coefficients,
            degree,
        }
    }

    /// Returns the degree of the polynomial
    pub const fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the coefficients of the polynomial
    pub const fn coefficients(&self) -> &[Coefficient] {
        &self.coefficients
    }

    /// Returns the coefficient of a given degree
    pub fn coefficient(&self, degree: usize) -> Option<bool> {
        self.coefficients()
            .get(degree / BITS_PER_COEFF)
            .copied()
            .map(|coeff| (coeff >> (degree % BITS_PER_COEFF)) & 1 == 1)
    }

    /// Evaluates the given polynomial at a given point
    pub fn evaluate(&self, x: bool) -> bool {
        if !x {
            // Panic
            // self.coefficient is guaranteed to be non-empty
            return self.coefficient(0).unwrap();
        }

        let mut count_ones = 0;
        for coeff in self.coefficients() {
            count_ones += coeff.count_ones();
        }

        (count_ones % 2) == 1
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
        let len = max_deg / BITS_PER_COEFF + 1;
        let mut result = vec![0; len].into_boxed_slice();

        for (i, rc) in result.iter_mut().enumerate() {
            let a = self.coefficients().get(i).copied().unwrap_or(0);
            let b = other.coefficients().get(i).copied().unwrap_or(0);
            *rc = a ^ b;
        }

        if self.degree() == other.degree() {
            Self::new(result)
        } else {
            // We know that the degree of the sum is exactly max(deg(p1), deg(p2)).
            Self {
                coefficients: result,
                degree: max_deg,
            }
        }
    }

    /// Multiply two polynomials together
    ///
    /// The reason this function exists outside of the `std::ops::Mul` trait is because
    /// it is interesting to multiply two polynomials without losing ownership of them.
    ///
    /// However, this function allocates a new polynomial.
    pub fn mul(&self, other: &Self) -> Self {
        // The degree of the product is deg(p1) + deg(p2).
        let result_len = (self.degree() + other.degree()) / BITS_PER_COEFF + 1;
        let mut result = vec![0; result_len].into_boxed_slice();

        for (i, &a) in self
            .coefficients()
            .iter()
            .take(self.degree() / BITS_PER_COEFF + 1)
            .enumerate()
        {
            for (j, &b) in other
                .coefficients()
                .iter()
                .take(other.degree() / BITS_PER_COEFF + 1)
                .enumerate()
            {
                let mut processed_a = a;

                if a & 1 == 1 {
                    result[i + j] ^= b;
                    processed_a ^= 1;
                }

                let mut local_result_h = 0; // Reduce cache misses
                while processed_a != 0 {
                    let k = processed_a.trailing_zeros() as usize;

                    result[i + j] ^= b << k;

                    // k is guaranteed to be non-zero
                    local_result_h ^= b >> (BITS_PER_COEFF - k);

                    processed_a &= processed_a - 1;
                }

                if i + j + 1 < result_len {
                    result[i + j + 1] ^= local_result_h;
                }
            }
        }

        Self {
            coefficients: result,
            degree: self.degree() + other.degree(),
        }
    }

    /// Compute the remainder of the division of two polynomials
    ///
    /// This function allocates a new polynomial.
    pub fn rem(&self, other: &Self) -> Self {
        let mut r = self.coefficients().to_vec().into_boxed_slice();
        let mut r_degree = self.degree();

        // At most self.degree() - other.degree() iterations
        while r_degree >= other.degree() {
            let shift = r_degree - other.degree();
            let block_shift = shift / BITS_PER_COEFF;
            let bit_shift = shift % BITS_PER_COEFF;

            let max_idx = other.degree() / BITS_PER_COEFF + 1;
            let max_bound = r.len() - block_shift - 1;
            for i in 0..max_idx {
                r[block_shift + i] ^= other.coefficients()[i] << bit_shift;
                if bit_shift != 0 && i < max_bound {
                    r[block_shift + i + 1] ^=
                        other.coefficients()[i] >> (BITS_PER_COEFF - bit_shift);
                }
            }

            // ~8x faster than `Self::compute_degree`
            while r_degree > 0 && (r[r_degree / BITS_PER_COEFF] >> (r_degree % BITS_PER_COEFF)) == 0
            {
                let bit_position = r_degree % BITS_PER_COEFF;

                // Panic
                // BITS_PER_COEFF - bit_position is at most BITS_PER_COEFF, which is a valid u32
                let shifted_coeff = r[r_degree / BITS_PER_COEFF]
                    .wrapping_shl(u32::try_from(BITS_PER_COEFF - bit_position).unwrap());

                r_degree = r_degree
                    .saturating_sub((shifted_coeff.leading_zeros() as usize).min(bit_position) + 1);
            }
        }

        Self {
            coefficients: r,
            degree: r_degree,
        }
    }

    /// Zeroize the polynomial
    ///
    /// It can be useful to zeroize on drop a struct represented by a polynomial
    /// if it is critical.
    ///
    /// ## Safety
    ///
    /// This function is unsafe because it writes zeroes to the memory
    /// pointed to by the coefficients.
    ///
    /// You should not use the polynomial after calling this function.
    pub unsafe fn zeroize(&mut self) {
        // Zeroize degree
        //
        // Safety
        // We are only writing into a single piece of memory.
        // It is equivalent to `self.degree = 0`, but volatile.
        unsafe {
            core::ptr::write_volatile(&mut self.degree, core::mem::zeroed());
        };

        // Zeroize coefficients
        let base_ptr = self.coefficients.as_mut_ptr();
        for i in 0..self.coefficients().len() {
            // Safety
            // We know the pointer is valid because it points to an area inside of the buffer,
            // as `i` is between 0 and len-1.
            // We are writing `size_of::<Coefficient>()` bytes of zeroes to a valid pointer
            // to a `Coefficient`.
            unsafe {
                core::ptr::write_volatile(base_ptr.add(i), core::mem::zeroed());
            };
        }
    }
}

impl Clone for Polynomial {
    fn clone(&self) -> Self {
        let relevant_length = self.degree() / BITS_PER_COEFF;

        let mut cloned_coefficients = Vec::with_capacity(relevant_length + 1);
        cloned_coefficients.extend_from_slice(&self.coefficients()[..=relevant_length]);

        Self {
            coefficients: cloned_coefficients.into_boxed_slice(),
            degree: self.degree(),
        }
    }
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        if self.degree() != other.degree() {
            return false;
        }

        let relevant_length = self.degree() / BITS_PER_COEFF + 1;
        self.coefficients()[..relevant_length] == other.coefficients()[..relevant_length]
    }
}

impl core::ops::Deref for Polynomial {
    type Target = [Coefficient];

    fn deref(&self) -> &Self::Target {
        self.coefficients()
    }
}

#[cfg(test)]
mod test {
    use super::{Coefficient, Polynomial, BITS_PER_COEFF};
    use alloc::boxed::Box;

    #[test]
    #[should_panic = "The vector of coefficients must not be empty."]
    fn test_new_empty() {
        Polynomial::new(Box::new([]));
    }

    #[test]
    fn test_compute_degree() {
        let coefficients = [0b10010];
        assert_eq!(Polynomial::compute_degree(&coefficients), 4);

        let coefficients = [0b10010, 0b1];
        assert_eq!(Polynomial::compute_degree(&coefficients), BITS_PER_COEFF);

        let coefficients = [0b10010, 0b0];
        assert_eq!(Polynomial::compute_degree(&coefficients), 4);
    }

    #[test]
    fn test_eq() {
        let p1 = Polynomial::new(Box::new([0b1001]));
        let p2 = Polynomial::new(Box::new([0b1001]));
        assert_eq!(p1, p2);

        let p1 = Polynomial::new(Box::new([0b1001, 0b1000_0011_0101_1010, 0b0, 0b1, 0b0]));
        let p2 = Polynomial::new(Box::new([0b1001, 0b1000_0011_0101_1010, 0b0, 0b1, 0b0]));
        assert_eq!(p1, p2);

        let p1 = Polynomial::new(Box::new([0b1001]));
        let p2 = Polynomial::new(Box::new([0b1001, 0b0]));
        assert_eq!(p1, p2);

        let p1 = Polynomial::new(Box::new([0b1001]));
        let p2 = Polynomial::new(Box::new([0b1000]));
        assert_ne!(p1, p2);

        let p1 = Polynomial::new(Box::new([0b1000, 0b10, 0b0]));
        let p2 = Polynomial::new(Box::new([0b1000, 0b0, 0b0]));
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_monomial() {
        let p = Polynomial::monomial(5);
        assert_eq!(Polynomial::compute_degree(p.coefficients()), 5);

        let p = Polynomial::monomial(BITS_PER_COEFF - 1);
        assert_eq!(
            Polynomial::compute_degree(p.coefficients()),
            BITS_PER_COEFF - 1
        );

        let p = Polynomial::monomial(BITS_PER_COEFF);
        assert_eq!(Polynomial::compute_degree(p.coefficients()), BITS_PER_COEFF);
    }

    #[test]
    fn test_random() {
        let p = Polynomial::random(5);
        assert_eq!(Polynomial::compute_degree(p.coefficients()), 5);

        let p = Polynomial::random(BITS_PER_COEFF);
        assert_eq!(Polynomial::compute_degree(p.coefficients()), BITS_PER_COEFF);
    }

    #[test]
    fn test_clone() {
        let p1 = Polynomial::new(Box::new([0b1001]));
        #[allow(clippy::redundant_clone)]
        let p2 = p1.clone();
        assert_eq!(p1, p2);

        let p1 = Polynomial::new(Box::new([0b1001, 0b1000_0011_0101_1010, 0b0, 0b1, 0b0]));
        #[allow(clippy::redundant_clone)]
        let p2 = p1.clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_evaluate() {
        let p = Polynomial::new(Box::new([0b1001]));
        assert!(!p.evaluate(true));
        assert!(p.evaluate(false));

        let p = Polynomial::new(Box::new([0b1111_00010, 0b1001]));
        assert!(p.evaluate(true));
        assert!(!p.evaluate(false));
    }

    #[test]
    fn test_add() {
        // Simple case
        let p1 = Polynomial::new(Box::new([0b1001]));
        let p2 = Polynomial::new(Box::new([0b0011]));
        let p3 = p1.add(&p2);
        assert_eq!(*p3.coefficients(), [0b1010]);

        // Multiple coefficients
        let p1 = Polynomial::new(Box::new([0b1001, 0b1]));
        let p2 = Polynomial::new(Box::new([0b0101, 0b1]));
        let p3 = p1.add(&p2);
        assert_eq!(*p3.coefficients(), [0b1100, 0b0]);
    }

    #[test]
    fn test_mul() {
        let p1 = Polynomial::new(Box::new([0b1001]));
        let p2 = Polynomial::new(Box::new([0b11]));
        let p3 = p1.mul(&p2);
        assert_eq!(*p3.coefficients(), [0b11011]);

        let p1 = Polynomial::new(Box::new([0b111]));
        let p2 = Polynomial::new(Box::new([0b11]));
        let p3 = p1.mul(&p2);
        assert_eq!(*p3.coefficients(), [0b1001]);

        let p1 = Polynomial::new(Box::new([Coefficient::MAX]));
        let p2 = Polynomial::new(Box::new([0b11]));
        let p3 = p1.mul(&p2);
        assert_eq!(*p3.coefficients(), [0b1, 0b1]);
    }

    #[test]
    fn test_rem() {
        let p1 = Polynomial::new(Box::new([0b1001]));
        let p2 = Polynomial::new(Box::new([0b11]));
        let p3 = p1.rem(&p2);
        assert!(p3.degree() < p2.degree());
        assert_eq!(*p3.coefficients(), [0]);

        let p1 = Polynomial::new(Box::new([0b1]));
        let p2 = Polynomial::new(Box::new([0b10]));
        let p3 = p1.rem(&p2);
        assert!(p3.degree() < p2.degree());
        assert_eq!(*p3.coefficients(), [1]);

        let p1 = Polynomial::new(Box::new([0b10_1010_1101]));
        let p2 = Polynomial::new(Box::new([0b11011]));
        let p3 = p1.rem(&p2);
        assert!(p3.degree() < p2.degree());
        assert_eq!(*p3.coefficients(), [0b1010]);
    }

    #[test]
    fn test_zeroize() {
        let mut p = Polynomial::new(Box::new([42, 42]));

        unsafe {
            p.zeroize();
        }

        // DO NOT USE p AFTER THIS
        // This is for test purposes only
        assert_eq!(p.degree(), 0);
        assert_eq!(*p.coefficients(), [0, 0]);
    }
}
