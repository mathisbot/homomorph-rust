# Homomorphic Encryption Scheme in Rust

This repository contains a Rust implementation of a homomorphic encryption scheme. 

Homomorphic encryption allows computations to be performed on encrypted data without decrypting it, preserving the privacy of the data.
Homomorphic encryption is still a subject of research today, and no system that is both secure and efficient has yet been found. Furthermore, random number generation is done via the `rand` crate, which is notoriously unsuitable for cryptographic use. For these reasons, this library should not be used in production.

Use with better-suited random-generation crates is WIP

## Features

- [X] Encryption of data
- [X] Decryption of encrypted data
- [ ] Homomorphic addition operation -> Tests don't pass
- [ ] Homomorphic multiplication operation

## Getting Started

### Prerequisites

- [Rust/Cargo](https://www.rust-lang.org/) (version ^1.77.2)

### Installation

1. Clone the repository:

    ```shell
    git clone https://github.com/your-username/homomorphic-encryption-rust.git
    ```

2. Build the project:

    ```shell
    cargo build
    ```

3. Run the tests:

    ```shell
    cargo test
    ```

4. If you want to use this crate as a module for your own crate, please refer to the documentation; where you'll also find examples :

    ```shell
    cargo doc
    ```

## Usage

To use the homomorphic encryption scheme in your Rust project, add the following to your `Cargo.toml` file:

## Architecture

```bash
homomorph
├───src
│   └───polynomial.rs # Polynomial module
│   └───lib.rs # Library
│   └───main.rs # Main file
```

## System

### Definition

The system is defined by 4 parameters :
$d, d', \delta < d, \tau \in \mathbb{N}$

A secret key $S$ is a randomly generated polynomial of degree $d$ in $\mathbb{Z}/2\mathbb{Z}_{d}[X]$.

A public key $T$ is $\tau$-list of polynomials in $\mathbb{Z}/2\mathbb{Z}_{d+d'}[X]$. These polynomials are generated as follows :

- Generate two random polynomials :
    - $Q_i \in \mathbb{Z}/2\mathbb{Z}_{d'}[X]$
    - $R_i \in \mathbb{Z}/2\mathbb{Z}_{\delta}[X]$
- $T_i$ is the sum $SQ_i + XR_i$

So that $T = (SQ_i + XR_i)_{1 \leq i \leq \tau}$

### Cipher

#### Encryption
Encryption of bit $x$ is done as follows :

- Generate $\mathcal{U} \in \mathcal{P}([1..\tau])$
- Encrypted polynomial is $C = (\sum_{i\in\mathcal{U}} T_i) + x$

$\mathcal{U}$ is used in order to protect against bruteforce. Indeed, if the sum was made over $[1..\tau]$, a malicious person could compute the cipher of $0$ and $1$ and easily compare them with the desired cipher. With $\mathcal{U}$ in the way, the number of possibilities is now $2^\tau$.

#### Decryption
Decryption of a cipher $C$ is done as follows :

- Compute $R$ the quotient of the euclidean division of $C$ by $S$
- $x$ is $R$ evaluated at $0$

This is why $\delta$ is under the condition $\delta < d$. Indeed, we recall that $C = \sum_{i\in\mathcal{U}} (SQ_i + XR_i) + x$, where $R_i$ has a degree of at most $\delta$, and $Q_i$ of at most $d'$. Thus, $R$ is exactly $(\sum_{i\in\mathcal{U}} XR_i) + x$, which gives $x$ when evaluated at $0$.

### Properties

This system is partially homomorphic, which means that it is not homomorphic with every operations.
However, one can prove that it is homomorphic with every [boolean function](https://en.wikipedia.org/wiki/Boolean_function#:~:text=In%20mathematics%2C%20a%20Boolean%20function,function\)%2C%20used%20in%20logic.) of degree less or equal than $\frac{d}{\delta}$.
