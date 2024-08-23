mod int;
mod uint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Represents homomorphic and gate over bits
pub struct HomomorphicAndGate;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Represents homomorphic or gate over bits
pub struct HomomorphicOrGate;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Represents homomorphic xor gate over bits
pub struct HomomorphicXorGate;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Represents homomorphic not gate over bits
pub struct HomomorphicNotGate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Represents homomorphic additive operation over numbers
pub struct HomomorphicAddition;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Represents homomorphic multiplicative operation over numbers
pub struct HomomorphicMultiplication;
