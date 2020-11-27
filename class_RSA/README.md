# RSA-bigint

An implementation of the RSA cryptosystem relying on the native JS (stage 3) implementation of BigInt. It can be used by any [Web Browser or webview supporting BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#Browser_compatibility) and with Node.js (>=10.4.0). In the latter case, for multi-threaded primality tests, you should use Node.js v11 or newer or enable at runtime with `node --experimental-worker` with Node.js version >= 10.5.0 and < 11.

_The operations supported on BigInts are not constant time. BigInt can be therefore **[unsuitable for use in cryptography](https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html).** Many platforms provide native support for cryptography, such as [Web Cryptography API](https://w3c.github.io/webcrypto/) or [Node.js Crypto](https://nodejs.org/dist/latest/docs/api/crypto.html)._

The RSA cryptosystem, named after and invented by Rivest–Shamir–Adleman in 1977. In such a cryptosystem, the encryption key is public and distinct from the decryption key which is kept secret (private). In RSA, this asymmetry is based on the practical difficulty of factoring the product of two large prime numbers, the "factoring problem".

## Key generation

1. Define the bit length of the modulus `n`, or `keyLength` in bits.
2. Choose two large prime numbers `p` and `q` randomly and independently of each other such that `gcd( p·q, (p-1)(q-1) )=1` and `n=p·q` has a key length of keyLength. For instance:
   1. Generate a random prime `p` with a bit length of `keyLength/2 + 1`.
   2. Generate a random prime `q` with a bit length of `keyLength/2`.
   3. Repeat until the bitlength of `n=p·q` is `keyLength`.
3. Compute Euler's totient function such that `phi(n) = (p-1)*(q-1)`.
4. Choose a comprime of `phi(n)` as the public exponent `e`:
   * Generate a simple `BigInt` number. Often is a predifined prime `e = 65537 = 2^16 + 1` 
5. Compute the private exponent `d` as `d = e^-1 mod(phi(n))`.
   
The **public** (encryption) **key** is **(e, n)**.

The **private** (decryption) **key** is **(d, n)**. 
  
## Encryption
Let `m` be the clear-text message,

* Compute ciphertext as: **`c = m^e mod(n)`**

## Decryption
Let `c` be the ciphertext to decrypt.

* Compute the plaintext message as: **`m = c^d mod(n)`**

## Installation
`npm install bigint-crypto-utils`

`npm install bigint-conversion`


* * *
