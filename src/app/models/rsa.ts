import { PrivateKey } from './private-key';
import { PublicKey } from './public-key';
import * as bcu from 'bigint-crypto-utils';
import * as bc from 'bigint-conversion';
import * as myrsa from 'class_RSA/src/index';

export class RSA {
    privateKey: PrivateKey;
    //publicKey: PublicKey;
    publicKey: PublicKey;
// Since we are working with BigInt values, subtract 1 as integer number is not valid, so we create a public constant
 _ONE = BigInt(1);
// We need to generate the coprime "e" in modulus phi(n)
 _E = BigInt(65537);

    constructor(
    ) {
      }

      async generateKeys(bitLength = 3072){
        let p, q, n, phi;

        // First step is to generate the public modulus as n = p * q
        do {
            p = await bcu.prime(Math.floor(bitLength / 2) + 1);
            q = await bcu.prime(Math.floor(bitLength / 2));
            n = p * q;
    
            // Second step is to compute Euler's totient function
            phi = (p - this._ONE) * (q - this._ONE);
    
    
        } while (q === p || bcu.bitLength(n) !== bitLength || !(bcu.gcd(this._E, phi) === this._ONE));
    
        let d = await bcu.modInv(this._E, phi);
    
        this.publicKey = new PublicKey(this._E, n);
        this.privateKey = new PrivateKey(d, this.publicKey.n);
    
        return {publicKey: this.publicKey, privateKey: this.privateKey};
          
      }

      encrypt(m) {
        m = bc.textToBigint(m);
        return bcu.modPow(m, this.publicKey.e, this.publicKey.n);
    }
    

    verify(s) {
        if (this.valVerifyPu(s)) {
            console.log("Message to verify > n");
            return null;
        } 
        else return bc.bigintToText(bcu.modPow(s, this.publicKey.e, this.publicKey.n));
    }

    decrypt(c) {
        if (this.valVerifyPr(c)) {
            console.log("Message to decrypt > n");
            return null;
        } 
        else return bc.bigintToText(bcu.modPow(c, this.privateKey.d, this.privateKey.n));
    }

    sign(h) {
        h = bc.textToBigint(h);
        if (this.valVerifyPr(h)) {
            console.log("Message to sign > n");
            return null;
        } 
        else return bcu.modPow(h, this.privateKey.d, this.privateKey.n);
    }


    valVerifyPu(m) {
        if ((m > this.publicKey.n))
            console.log("message is greater than n");
        return m > this.publicKey.n;
    }

    valVerifyPr(m) {
        if ((m > this.privateKey.n))
            console.log("message is greater than n");
        return m > this.privateKey.n;
    }


}
