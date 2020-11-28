import * as bcu from 'bigint-crypto-utils';
import * as bc from 'bigint-conversion';


export class PrivateKey {
    d;
    n;
  
    constructor(d, n) {
      this.d = d;
      this.n = n;
    }

    decrypt(c) {    
        c= bc.hexToBigint(c) 
        return bc.bigintToText(bcu.modPow(c, this.d, this.n));
    }

    sign(h) {
        h = bc.textToBigint(h);
        if (this.valVerify(h)) {
            console.log("Message to sign > n");
            return null;
        } 
        else return bcu.modPow(h, this.d, this.n);
    }
    signsinconv(h) {
        if (this.valVerify(h)) {
            console.log("Message to sign > n");
            return null;
        } 
        else return bcu.modPow(h, this.d, this.n);
    }
    valVerify(m) {
        if ((m > this.n))
            console.log("message is greater than n");
        return m > this.n;
    }


}
