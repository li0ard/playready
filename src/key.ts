import type { CipherType, KeyType } from "./const.js";

const swapEndianess = (data: Uint8Array): Uint8Array => new Uint8Array([
    data[3], data[2], data[1], data[0],
    data[5], data[4],
    data[7], data[6],
    data[8], data[9],
    ...data.slice(10, 16)
]);

/** Key instance */
export class Key {
    /** Key ID */
    public kid: Uint8Array;
    /**
     * Key instance
     * @param kid Key ID
     * @param type Key type
     * @param cipher Cipher type
     * @param key Key
     */
    constructor(
        kid: Uint8Array,
        public type: KeyType,
        public cipher: CipherType,
        public key: Uint8Array
    ) { this.kid = swapEndianess(kid); }
}