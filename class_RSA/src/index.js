'use strict';

import * as bcu from 'bigint-crypto-utils';
import * as bc from 'bigint-conversion';
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
export const generateRandomKeys = async function (bitLength = 3072) {
    let p, q, n, phi;

    // First step is to generate the public modulus as n = p * q
    do {
        p = await bcu.prime(Math.floor(bitLength / 2) + 1);
        q = await bcu.prime(Math.floor(bitLength / 2));
        n = p * q;

        // Second step is to compute Euler's totient function
        phi = (p - _ONE) * (q - _ONE);


    } while (q === p || bcu.bitLength(n) !== bitLength || !(bcu.gcd(_E, phi) === _ONE));

    let d = await bcu.modInv(_E, phi);

    const publicKey = new PublicKey(_E, n);
    const privateKey = new PrivateKey(d, publicKey);

    return {publicKey: publicKey, privateKey: privateKey};
};

/**
 * Class for a RSA PublicKey
 */
export const PublicKey = class PublicKey {

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
        return bcu.modPow(m, this.e, this.n);
    }

    /**
     * Verify a given signed message
     *
     * @param {bigint} s signed message
     * @returns {bigint} m bigint message
     **/
    verify (s) {
        return bcu.modPow(s, this.e, this.n);
    }

};

/**
 * Class for a RSA PrivateKey
 */
export const PrivateKey = class PrivateKey {

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
        return bcu.modPow(c, this.d, this.publicKey.n);
    }

    /**
     * Sign a given message
     *
     * @param {bigint} m message to sign
     * @returns {bigint} s message signed
     **/
    sign (m) {
        return bcu.modPow(m, this.d, this.publicKey.n);
    }
};

/**
 * RSA keypair test
 * @param {bigint} m message to test
 * @param {KeyPair} kp keyPair of public and private keys
 * @returns {Promise<boolean>}
 */
export const test = async function test (m, kp) {
    let encryption = kp.publicKey.encrypt(m);
    let clearText = kp.privateKey.decrypt(encryption);
    let signature = kp.privateKey.sign(m);
    let verification = kp.publicKey.verify(signature);
    if(clearText === m && verification === m) {
        return {
            clearText: bc.bigintToText(m),
            encrypted: bc.bigintToText(encryption),
            decrypted: bc.bigintToText(clearText),
            signed: bc.bigintToText(signature),
            verified: bc.bigintToText(verification),
            status: 'OK'
        };
    }
    else {
        return {
            clearText: bc.bigintToText(m),
            encrypted: bc.bigintToText(encryption),
            decrypted: bc.bigintToText(clearText),
            signed: bc.bigintToText(signature),
            verified: bc.bigintToText(verification),
            status: 'Something went wrong'
        };
    }
};

