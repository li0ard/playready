import { ECCKey } from "./ecckey.js";
import { concatBytes, numberToBytesBE } from "@noble/curves/utils.js";
import type { AffinePoint } from "@noble/curves/abstract/curve.js";
import { cbc } from "@noble/ciphers/aes.js";
import { WMRM_SERVER_KEY } from "../const.js";
import { ElGamal } from "./elgamal.js";

export class XMLKey {
    private _point: ECCKey;
    aes_iv: Uint8Array;
    aes_key: Uint8Array;

    constructor() {
        this._point = ECCKey.generate();

        const xBytes = numberToBytesBE(this._point.publicKey.x, 32);
        this.aes_iv = xBytes.subarray(0,16);
        this.aes_key = xBytes.subarray(16,32);
    }

    get point(): AffinePoint<bigint> { return this._point.publicKey; }

    get encryptedWithWMRM(): Uint8Array {
        const encrypted = ElGamal.encrypt(this.point, WMRM_SERVER_KEY);

        return concatBytes(
            numberToBytesBE(encrypted.point1.x, 32), numberToBytesBE(encrypted.point1.y, 32),
            numberToBytesBE(encrypted.point2.x, 32), numberToBytesBE(encrypted.point2.y, 32)
        );
    }

    encrypt(data: Uint8Array | string): Uint8Array {
        if(typeof data == "string") data = new TextEncoder().encode(data);
        const ciphertext = cbc(this.aes_key, this.aes_iv).encrypt(data);
        
        return concatBytes(this.aes_iv, ciphertext);
    }
}