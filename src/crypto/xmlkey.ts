import { ECCKey } from "./ecckey.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import type { AffinePoint } from "@noble/curves/abstract/curve.js";

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
}