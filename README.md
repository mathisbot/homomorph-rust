# Homomorphic Encryption Scheme in Rust

This repository contains a Rust implementation of an homomorphic encryption scheme targetting unsigned integers (other types of numbers are WIP).

Homomorphic encryption allows computations to be performed on encrypted data without decrypting it, preserving the privacy of the data.
Homomorphic encryption is still a subject of research today, and no system that is both secure and efficient has yet been found.

I might also rewrite the system to use binary representation of numbers instead of polynomials for increased performance but same outcome.

## Features

- [X] Encryption/Decryption
- [X] Homomorphic addition for `uint`
- [ ] Homomorphic multiplication for `uint`
- [ ] Other types of numbers

## Getting Started

### Prerequisites

- [Rust/Cargo](https://www.rust-lang.org/)

### Installation

I do not intend to publish the crate on `crates.io`.

1. Clone the repository:

    ```shell
    git clone https://github.com/your-username/homomorphic-encryption-rust.git
    ```

2. Build the project:

    ```shell
    cargo build --lib --release
    ```

3. Run the tests:

    ```shell
    cargo test
    ```

### Usage

4. If you want to use this crate as a module for your own crate, please refer to the documentation, where you'll also find examples :

    ```shell
    cargo doc
    ```

## Benchmarks

Benchmarks were made using a Ryzen 7 7800x3D on Windows 11 by averaging on 10 000 tries on `usize` (`u64`) data.

Parameters used for this benchmark were the ones that should be used for a standard application :
- `d` = 512
- `dp` = 128
- `delta` = 16
- `tau` = 256.

| Operation         | Average time     |
|:-----------------:|:----------------:|
| Encryption        |      129.8 µs    |
| Decryption        |      12.5 µs     |
| Dec. after op.    |      582.0 µs    |
| Add as uint       |      3.9 ms      |
| Mul               |   Unimplemented  |


It is still more efficient to decrypt, operate and then re-encrypt the data. This limits the use of the system to applications where security is paramount, and takes precedence over speed.

It's worth remembering that the system is inherently slow, as each bit is ciphered as a polynomial whose degree is $d+d'$.
Hence, it takes more than 160 bytes for $d+d'=640$. This makes operations computationally heavy.

## System

For more information about what homomorphic encryption schemes are, see [Wikipedia](https://en.wikipedia.org/wiki/Homomorphic_encryption).

### Definition

The system is defined by 4 parameters :
$d, d', \delta < d, \tau \in \mathbb{N}$

A secret key $S$ is a randomly generated polynomial of degree $d$ in $\mathbb{Z}/2\mathbb{Z}_{d}[X]$.

A public key $T$ is a $\tau$-list of polynomials in $\mathbb{Z}/2\mathbb{Z}_{d+d'}[X]$. These polynomials are generated as follows :

- Generate two random polynomials :
    - $Q_i \in \mathbb{Z}/2\mathbb{Z}_{d'}[X]$
    - $R_i \in \mathbb{Z}/2\mathbb{Z}_{\delta}[X]$
- $T_i$ is the sum $SQ_i + XR_i$

So that $T = (SQ_i + XR_i)_{1 \leq i \leq \tau}$

### Cipher

#### Encryption
Encryption of bit $x$ is done as follows :

- Generate $\mathcal{U} \in \mathcal{P}([1,\tau])$
- Encrypted polynomial is $C = (\sum_{i\in\mathcal{U}} T_i) + x$

$\mathcal{U}$ is used in order to protect against bruteforce. Indeed, if the sum was made over $[1,\tau]$, a malicious person could compute the cipher of $0$ and $1$ and easily compare them with the desired cipher. With $\mathcal{U}$ in the way, the number of possibilities is now $2^\tau$.

#### Decryption
Decryption of a cipher $C$ is done as follows :

- Compute $R$ the quotient of the euclidean division of $C$ by $S$
- $x$ is $R$ evaluated at $0$

This is why $\delta$ is under the condition $\delta < d$. Indeed, we recall that $C = \sum_{i\in\mathcal{U}} (SQ_i + XR_i) + x$, where $R_i$ has a degree of at most $\delta$, and $Q_i$ of at most $d'$. Thus, $R$ is exactly $(\sum_{i\in\mathcal{U}} XR_i) + x$, which gives $x$ when evaluated at $0$.

### Security

Encryption schemes security is complex to quantify. However, we can be sure of a system's insecurity if, for example, it is possible to: retrieve the private key from one or more public keys; retrieve the plaintext of an encrypted message without having the private key, ...

In our case, let's look at the potential loopholes.

#### Retrieving $S$ with $T$

Retrieving the private key with only the public key (or a set of them) is equivalent to solving the problem [RLWE](https://en.wikipedia.org/wiki/Ring_learning_with_errors) (thus the shape of our public key). This problem has been proved as computationally infisible, which means that no current machine, and no machine that may soon be developed, can solve it in a time that is humanly conceivable. Great!

#### Retrieving $x$ with only $T$

Often, bruteforce or the use of order relations compatible with the encryption function can be used to break the encryption. In our case, the parameter $\mathcal{U}$ is used to confuse and increase the $2^\tau$ the number of possibilities.

#### $\tau$

In view of the preceding discussions, it would seem advisable to choose a $\tau$ greater than $128$, or even $256$ for more sensitive applications.

### Properties

This system is partially homomorphic, which means that it is not homomorphic with every operations.
However, one can prove that it is homomorphic with every [boolean function](https://en.wikipedia.org/wiki/Boolean_function#:~:text=In%20mathematics%2C%20a%20Boolean%20function,function\)%2C%20used%20in%20logic.) of degree less or equal than $\frac{d}{\delta}$.

## Extension

Our system targets bits. If we want to deal with integers, floats, strings, ... we need to extend the system. We can easily take advantage of the intuitive binary representation of objects in computers.

Let's have a look at how to implement the system for integers.

#### Addition

Proceeding in a similar way to a processor, we can reduce the addition of integer ciphers (i.e. lists of ciphered bits) to the application of serial logic gates to the bits. It's then easy to find the Boolean function relating to the application of these gates. One can notice that the AND gate corresponds to multiplying two ciphers, XOR to adding two ciphers, and OR to adding the sum and the product of two ciphers.

By playing with the same adder patterns that are in our ALU, we can easily recreate a working addition for our ciphers.

It seems that addition has a "boolean degree" of around 20, so you must have $\dfrac{d}{\delta}>20$ in order to use homomorphic addition. I recommend having it around over 32.

#### Multiplication

Imitating a processor seems to be a winning strategy. 
By repeating the above process with multiplication, it's fairly easy to implement (modulo the complexity of processor multipliers).
 