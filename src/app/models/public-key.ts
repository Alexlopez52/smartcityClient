import * as bcu from 'bigint-crypto-utils';
import * as bc from 'bigint-conversion';

export class PublicKey {
    e;
    n;
    _n2;
  
    constructor(e, n) {
      this.e = e;
      this.n = n;
      this._n2 = this.n ** BigInt(2) // cache n^2
    }

    encrypt(m) {
        m = bc.textToBigint(m);
        if (this.valVerify(m)) {
            console.log("Message to encrypt > n");
            return null;
        } 
        else return bcu.modPow(m, this.e, this.n);
    }
    encryptsinconv(m) { //antes havia un hextobigint si algo falla puede ser eso
        if (this.valVerify(m)) {
            console.log("Message to encrypt > n");
            return null;
        } 
        else return bcu.modPow(m, this.e, this.n);
    }

    verify(s) {
        if (this.valVerify(s)) {
            console.log("Message to verify > n");
            return null;
        } 
        else return bcu.modPow(s, this.e, this.n);
    }


    valVerify(m) {
        if ((m > this.n))
            console.log("message is greater than n");
        return m > this.n;
    }

}
