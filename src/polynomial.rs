//! A module for polynomial operations over Z/2Z\[X\].
//! 
//! A polynomial is represented as a vector of coefficients, where the i-th element is the coefficient of x^i.
//! 
//! # Examples
//! 
//! ```
//! use homomorph::polynomial::Polynomial;
//! 
//! let p = Polynomial::new(vec![true, false, false, true]);
//! ```
//! 
//! # Note
//! 
//! The majority of the functions are private and are used internally by the library.
//! You can still use the struct to handle the content of the keys to save them.

use std::ops::{Add, Deref, Mul};

// A polynomial over Z/2Z.
// A polynomial is represented as a vector of coefficients, where the i-th element is the coefficient of x^i.
pub struct Polynomial {
    coefficients: Vec<bool>, // Isn't guaranteed to be of size degree+1.
    degree: usize, // The exact degree of the polynomial.
}

fn get_degree(coefficients: &[bool]) -> usize {
    for i in (0..coefficients.len()).rev() {
        if coefficients[i] {
            return i;
        }
    }
    0
}

impl Polynomial {
    /// Create a new polynomial from a vector of coefficients.
    /// 
    /// # Arguments
    /// 
    /// * `coefficients` - A vector of coefficients.
    /// 
    /// # Returns
    /// 
    /// A new polynomial.
    /// 
    /// # Panics
    /// 
    /// Panics if the vector of coefficients is empty.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use homomorph::polynomial::Polynomial;
    /// 
    /// let p = Polynomial::new(vec![true, false, false, true]);
    /// ```
    /// 
    /// # Note
    /// 
    /// Takes ownership of the vector of coefficients.
    pub fn new(coefficients: Vec<bool>) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        let degree = get_degree(&coefficients);
        Polynomial { coefficients, degree }
    }

    /// Get the degree of the polynomial.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Get the coefficients of the polynomial.
    /// 
    /// # Returns
    /// 
    /// A reference to the vector of coefficients.
    pub fn coefficients(&self) -> &Vec<bool> {
        &self.coefficients
    }

    // We trust the user to provide the correct degree.
    pub(crate) unsafe fn new_unchecked(coefficients: Vec<bool>, degree: usize) -> Self {
        if coefficients.is_empty() {
            panic!("The vector of coefficients must not be empty.");
        }
        Polynomial { coefficients, degree }
    }

    pub(crate) fn random(degree: usize, rng: &mut impl rand::Rng) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        for _ in 0..=degree {
            coefficients.push(rng.gen::<bool>());
        }
        unsafe { Polynomial::new_unchecked(coefficients, degree) }
    }

    pub(crate) fn null() -> Self {
        Polynomial { coefficients: vec![false], degree: 0 }
    }

    fn clone_fn(&self) -> Polynomial {
        let mut cloned_coefficients = Vec::with_capacity(self.degree + 1);
        for i in 0..=self.degree {
            cloned_coefficients.push(self.coefficients[i]);
        }
        unsafe { Polynomial::new_unchecked(cloned_coefficients, self.degree) }
    }

    pub(crate) fn evaluate(&self, x: bool) -> bool {
        // If the evaluation is done at 0, the result is the constant term.
        if x == false {
            return self.coefficients[0];
        }
        // Horner's method for polynomial evaluation.
        let mut result = self.coefficients[self.degree];
        for i in (0..self.degree).rev() {
            result = result ^ (self.coefficients[i] & x);
        }
        result
    }

    pub(crate) fn add_fn(&self, other: &Polynomial) -> Polynomial {
        // We know that degree of the sum is at most max(deg(p1), deg(p2)).
        let max_deg = std::cmp::max(self.degree, other.degree);
        let mut result = Vec::with_capacity(max_deg + 1);
        for i in 0..=max_deg {
            let mut coeff = false;
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

    pub(crate) fn mul_fn(&self, other: &Polynomial) -> Polynomial {
        // The degree of the product is deg(p1) + deg(p2).
        let sum_deg = self.degree + other.degree;
        let mut result = vec![false; sum_deg+1];

        /*for (i, a) in self.coefficients.iter().enumerate().take(self.degree+1) {
            for (j, b) in other.coefficients.iter().enumerate().take(other.degree+1) {
                result[i + j] ^= a & b;
            }
        }*/
        for (i, _) in self.coefficients.iter().enumerate().take(self.degree + 1).filter(|(_, &a)| a) {
            for (j, _) in other.coefficients.iter().enumerate().take(other.degree + 1).filter(|(_, &b)| b) {
                result[i + j] ^= true; // a & b est true, donc XOR avec true
            }
        }
        unsafe { Polynomial::new_unchecked(result, sum_deg) }
    }

    pub(crate) fn rem(&self, other: &Polynomial) -> Polynomial {
        let mut self_coefficients = self.coefficients.clone();
        let mut other_coefficients = other.coefficients.clone();
        let mut last_index = other_coefficients.len();
        while last_index > 0 && !other_coefficients[last_index - 1] {
            last_index -= 1;
        }
        other_coefficients.truncate(last_index);

        let ocl = other_coefficients.len();

        while self_coefficients.len() >= ocl {
            let diff = self_coefficients.len() - ocl;
            for i in 0..other_coefficients.len() {
                if other_coefficients[i] {
                    // XOR operation for division
                    self_coefficients[i + diff] ^= other_coefficients[i];
                }
            }
            let mut last_index = self_coefficients.len();
            while last_index > 0 && !self_coefficients[last_index - 1] {
                last_index -= 1;
            }
            self_coefficients.truncate(last_index);
        }

        if self_coefficients.is_empty() {
            return Polynomial::null();
        }

        // Return the remainder polynomial
        let deg = self_coefficients.len() - 1;
        unsafe { Polynomial::new_unchecked(self_coefficients, deg) }
    }

    // Unused
    /*pub(crate) fn bit_and(&self, other: &Polynomial) -> Polynomial {
        self.mul_fn(other)
    }*/

    pub(crate) fn bit_xor(&self, other: &Polynomial) -> Polynomial {
        self.add_fn(other)
    }

    // Unused
    /*pub(crate) fn bit_or(&self, other: &Polynomial) -> Polynomial {
        self.add_fn(other) + self.mul_fn(other)
    }*/
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
        self.clone_fn()
    }
}

impl Deref for Polynomial {
    type Target = Vec<bool>;

    fn deref(&self) -> &Vec<bool> {
        &self.coefficients
    }
}


#[cfg(test)]
mod test {
    use super::Polynomial;
    use rand;

    #[test]
    fn test_get_degree() {
        let coefficients = vec![true, false, false, true, false, false];
        assert_eq!(super::get_degree(&coefficients), 3);
    }

    #[test]
    fn test_new() {
        let p = Polynomial::new(vec![true, false, false, true, false]);
        assert_eq!(p.degree, 3);
    }

    #[test]
    #[should_panic]
    fn test_new_panic() {
        let _ = Polynomial::new(vec![]);
    }

    #[test]
    fn test_new_unchecked() {
        unsafe { let _ = Polynomial::new_unchecked(vec![true, false, false, true, false], 3); }
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
        assert_eq!(p.degree, 5);
    }

    #[test]
    fn test_null() {
        let p = Polynomial::null();
        assert_eq!(p.degree, 0);
        assert_eq!(p.coefficients, vec![false]);
    }

    #[test]
    fn test_clone_fn() {
        let p1 = Polynomial::new(vec![true, false, false, true]);
        let p2 = p1.clone_fn();
        assert_eq!(p1.coefficients, p2.coefficients);
    }

    #[test]
    fn test_evaluate() {
        let p = Polynomial::new(vec![true, false, false, true]);
        assert_eq!(p.evaluate(true), false);
        assert_eq!(p.evaluate(false), true);
    }

    #[test]
    fn test_add_fn() {
        let p1 = Polynomial::new(vec![true, false, false, true]);
        let p2 = Polynomial::new(vec![true, true]);
        let p3 = p1.add_fn(&p2);
        assert_eq!(p3.coefficients, vec![false, true, false, true]);
        
        let p1 = Polynomial::new(vec![true, false, false, true]);
        let p2 = Polynomial::new(vec![false, true, false, true]);
        let p3 = p1.add_fn(&p2);
        assert!(p3.degree < p1.degree);
        assert_eq!(p3.coefficients, vec![true, true, false, false]);
    }

    #[test]
    fn test_mul_fn() {
        let p1 = Polynomial::new(vec![true, false, false, true]);
        let p2 = Polynomial::new(vec![true, true]);
        let p3 = p1.mul_fn(&p2);
        assert_eq!(p3.coefficients, vec![true, true, false, true, true]);
        
        let p1 = Polynomial::new(vec![true, true, true]);
        let p2 = Polynomial::new(vec![true, true]);
        let p3 = p1.mul_fn(&p2);
        assert_eq!(p3.coefficients, vec![true, false, false, true]);
    }

    #[test]
    fn test_rem() {
        let p1 = Polynomial::new(vec![true, false, false, true]);
        let p2 = Polynomial::new(vec![true, true]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree < p2.degree);
        assert_eq!(p3.coefficients, vec![false]);
        
        let p1 = Polynomial::new(vec![false, false, false, true]);
        let p2 = Polynomial::new(vec![true, true]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree < p2.degree);
        assert_eq!(p3.coefficients, vec![true]);
        
        let p1 = Polynomial::new(vec![false, false, true, false, true, true, false, true, false, true, false, true]);
        let p2 = Polynomial::new(vec![true, true, false, true, true]);
        let p3 = p1.rem(&p2);
        assert!(p3.degree < p2.degree);
        assert_eq!(p3.coefficients, vec![true, false, true]);
    }
}