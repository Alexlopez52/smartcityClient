import { Injectable } from '@angular/core';
import { Ambiente } from './ambiente';
import {HttpClient, HttpHeaders} from "@angular/common/http";
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class CasoService {
  private headers = new HttpHeaders({
    'Content-Type': 'application/json',
  });
  ambiente: Ambiente;  

  constructor(private http: HttpClient) {
    this.ambiente = new Ambiente();
   }
/////////////////////////AES/////////////////////////////////////
   postCaso(addcaso: string, iv :string){//: Observable<void> 
    let c = {addcaso , iv}
    console.log(c)
    return this.http.post(this.ambiente.urlCaso + '/addPost', {addcaso, iv, headers: this.headers});
  }

  getFrase(): Observable<Object>{  //esto es el observable. me da un array de studnets
    return this.http.get<Object>(this.ambiente.urlCaso + '/getFrase');  
    }

 /////////////////////////RSA/////////////////////////////////////
  postCasoRSA(body: object) {
  return this.http.post(this.ambiente.urlCaso + '/addPostRSA', body);
    }
  
    

  postSignRSA(body: object) {
    return this.http.post(this.ambiente.urlCaso + '/sign', body);
    }

  getFraseRSA() {
    return this.http.get(this.ambiente.urlCaso + '/getFraseRSA');
    }

  postpubKey(body: object) {  //send publicKey del cliente al servidor para encryptar mensaje
      return this.http.post(this.ambiente.urlCaso + '/postpubKey', body);
        }

  getpublicKeyRSA() {
    return this.http.get(this.ambiente.urlCaso + '/publickey');
    }

///////////////////////////////////FIRMA CIEGA/////////////////////////////////////////
  postSignCiega(body: object) {
    return this.http.post(this.ambiente.urlCaso + '/signCiega', body);
    }
  
///////////////////////////////////NO REPUDIO/////////////////////////////////////////
  postCasoRSANoRepudio(body: object) {
    return this.http.post(this.ambiente.urlCaso + '/addPostNoRepudio', body);
      }
  postCasoNoRepudioTipo3(body: object) {
      return this.http.post(this.ambiente.urlTtp + '/postTTP', body);
    }    
  getpublicKeyTTP(){
    return this.http.get(this.ambiente.urlTtp + '/publickey');
    }
  postpubKeyTTP(body: object) {  //send publicKey del cliente al servidor para encryptar mensaje
      return this.http.post(this.ambiente.urlTtp + '/postpublicKey', body);
        }

///////////////////////////////PAILLIER (homomorphic encryption) ///////////////////////////////////////////////
  postsumPaillier(suma: object) {  //
      return this.http.post(this.ambiente.urlCaso + '/postpaillierSum', suma);
        }

  }
