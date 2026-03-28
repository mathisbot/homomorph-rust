mod common;
mod int;
mod uint;

use crate::operations::OperationRequirement;

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

impl OperationRequirement for HomomorphicAndGate {
    const MIN_D_OVER_DELTA: u16 = 2;
}

impl OperationRequirement for HomomorphicOrGate {
    const MIN_D_OVER_DELTA: u16 = 2;
}

impl OperationRequirement for HomomorphicXorGate {
    const MIN_D_OVER_DELTA: u16 = 1;
}

impl OperationRequirement for HomomorphicNotGate {
    const MIN_D_OVER_DELTA: u16 = 1;
}

impl OperationRequirement for HomomorphicAddition {
    const MIN_D_OVER_DELTA: u16 = 21;
}

impl OperationRequirement for HomomorphicMultiplication {
    // Conservative default until precise bounds are fully documented.
    const MIN_D_OVER_DELTA: u16 = 64;
}
