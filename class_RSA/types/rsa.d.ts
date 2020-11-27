export type KeyPair = {
    /**
     * - a RSA public key
     */
    publicKey: {
        e: any;
        n: any;
        /**
         * Encrypt a given message
         *
         * @param {bigint} m message to encrypt
         * @returns {bigint} message encrypted
         **/
        encrypt(m: bigint): bigint;
        /**
         * Verify a given signed message
         *
         * @param {bigint} s signed message
         * @returns {bigint} m bigint message
         **/
        verify(s: bigint): bigint;
    };
    /**
     * - the associated RSA private key
     */
    privateKey: {
        d: any;
        publicKey: {
            e: any;
            n: any;
            /**
             * Encrypt a given message
             *
             * @param {bigint} m message to encrypt
             * @returns {bigint} message encrypted
             **/
            encrypt(m: bigint): bigint;
            /**
             * Verify a given signed message
             *
             * @param {bigint} s signed message
             * @returns {bigint} m bigint message
             **/
            verify(s: bigint): bigint;
        };
        /**
         * Decrypt a given encrypted message
         *
         * @param {bigint} c message encrypted
         * @returns {bigint} m message decrypted
         **/
        decrypt(c: bigint): bigint;
        /**
         * Sign a given message
         *
         * @param {bigint} m message to sign
         * @returns {bigint} s message signed
         **/
        sign(m: bigint): bigint;
    };
};
/**
 * Class for a RSA PrivateKey
 */
export const PrivateKey: {
    new (d: number | bigint, publicKey: {
        e: any;
        n: any;
        /**
         * Encrypt a given message
         *
         * @param {bigint} m message to encrypt
         * @returns {bigint} message encrypted
         **/
        encrypt(m: bigint): bigint;
        /**
         * Verify a given signed message
         *
         * @param {bigint} s signed message
         * @returns {bigint} m bigint message
         **/
        verify(s: bigint): bigint;
    }): {
        d: any;
        publicKey: {
            e: any;
            n: any;
            /**
             * Encrypt a given message
             *
             * @param {bigint} m message to encrypt
             * @returns {bigint} message encrypted
             **/
            encrypt(m: bigint): bigint;
            /**
             * Verify a given signed message
             *
             * @param {bigint} s signed message
             * @returns {bigint} m bigint message
             **/
            verify(s: bigint): bigint;
        };
        /**
         * Decrypt a given encrypted message
         *
         * @param {bigint} c message encrypted
         * @returns {bigint} m message decrypted
         **/
        decrypt(c: bigint): bigint;
        /**
         * Sign a given message
         *
         * @param {bigint} m message to sign
         * @returns {bigint} s message signed
         **/
        sign(m: bigint): bigint;
    };
};
/**
 * Class for a RSA PublicKey
 */
export const PublicKey: {
    new (e: number | bigint, n: number | bigint): {
        e: any;
        n: any;
        /**
         * Encrypt a given message
         *
         * @param {bigint} m message to encrypt
         * @returns {bigint} message encrypted
         **/
        encrypt(m: bigint): bigint;
        /**
         * Verify a given signed message
         *
         * @param {bigint} s signed message
         * @returns {bigint} m bigint message
         **/
        verify(s: bigint): bigint;
    };
};
export function generateRandomKeys(bitLength$1?: number): Promise<any>;
export function test(m: bigint, kp: KeyPair): Promise<boolean>;
