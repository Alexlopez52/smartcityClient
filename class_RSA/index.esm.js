import { bitLength, gcd, prime, modInv, modPow } from 'bigint-crypto-utils';
import { bigintToText } from 'bigint-conversion';

// Since we are working with BigInt values, subtract 1 as integer number is not valid, so we create a public constant
const _ONE = BigInt(1);
// We need to generate the coprime "e" in modulus phi(n)
const _E = BigInt(65537);

/**
 * @typedef {Object} KeyPair
 * @property {PublicKey} publicKey - a RSA public key
 * @property {PrivateKey} privateKey - the associated RSA private key
 */

/**
 * Generate Random Keys function
 * @param {number} bitLength
 * @returns {Promise} a promise that resolves to a {@link KeyPair} of public, private keys
 */
const generateRandomKeys = async function (bitLength$1 = 3072) {
    let p, q, n, phi;

    // First step is to generate the public modulus as n = p * q
    do {
        p = await prime(Math.floor(bitLength$1 / 2) + 1);
        q = await prime(Math.floor(bitLength$1 / 2));
        n = p * q;

        // Second step is to compute Euler's totient function
        phi = (p - _ONE) * (q - _ONE);


    } while (q === p || bitLength(n) !== bitLength$1 || !(gcd(_E, phi) === _ONE));

    let d = await modInv(_E, phi);

    const publicKey = new PublicKey(_E, n);
    const privateKey = new PrivateKey(d, publicKey);

    return {publicKey: publicKey, privateKey: privateKey};
};

/**
 * Class for a RSA PublicKey
 */
const PublicKey = class PublicKey {

    /**
     * Creates an instance of class RSAPublicKey
     * @param {bigint | number} e public exponent
     * @param {bigint | number} n public modulus
     */
    constructor(e, n) {
        this.e = BigInt(e);
        this.n = BigInt(n);
    }

    /**
     * Encrypt a given message
     *
     * @param {bigint} m message to encrypt
     * @returns {bigint} message encrypted
     **/
    encrypt (m) {
        return modPow(m, this.e, this.n);
    }

    /**
     * Verify a given signed message
     *
     * @param {bigint} s signed message
     * @returns {bigint} m bigint message
     **/
    verify (s) {
        return modPow(s, this.e, this.n);
    }

};

/**
 * Class for a RSA PrivateKey
 */
const PrivateKey = class PrivateKey {

    /**
     * Creates an instance of class RSAPrivateKey
     * @param {bigint | number} d private exponent
     * @param {PublicKey} publicKey
     */
    constructor (d, publicKey) {
        this.d = BigInt(d);
        this.publicKey = publicKey;
    }

    /**
     * Decrypt a given encrypted message
     *
     * @param {bigint} c message encrypted
     * @returns {bigint} m message decrypted
     **/
    decrypt (c) {
        return modPow(c, this.d, this.publicKey.n);
    }

    /**
     * Sign a given message
     *
     * @param {bigint} m message to sign
     * @returns {bigint} s message signed
     **/
    sign (m) {
        return modPow(m, this.d, this.publicKey.n);
    }
};

/**
 * RSA keypair test
 * @param {bigint} m message to test
 * @param {KeyPair} kp keyPair of public and private keys
 * @returns {Promise<boolean>}
 */
const test = async function test (m, kp) {
    let encryption = kp.publicKey.encrypt(m);
    let clearText = kp.privateKey.decrypt(encryption);
    let signature = kp.privateKey.sign(m);
    let verification = kp.publicKey.verify(signature);
    if(clearText === m && verification === m) {
        return {
            clearText: bigintToText(m),
            encrypted: bigintToText(encryption),
            decrypted: bigintToText(clearText),
            signed: bigintToText(signature),
            verified: bigintToText(verification),
            status: 'OK'
        };
    }
    else {
        return {
            clearText: bigintToText(m),
            encrypted: bigintToText(encryption),
            decrypted: bigintToText(clearText),
            signed: bigintToText(signature),
            verified: bigintToText(verification),
            status: 'Something went wrong'
        };
    }
};

export { PrivateKey, PublicKey, generateRandomKeys, test };
