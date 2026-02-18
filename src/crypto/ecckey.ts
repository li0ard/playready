import type { AffinePoint } from "@noble/curves/abstract/curve.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { p256 } from "@noble/curves/nist.js";
import { bytesToNumberBE, concatBytes, numberToBytesBE, randomBytes } from "@noble/curves/utils.js";
import { ElGamal } from "./elgamal.js";

export class ECCKey {
    public publicKey: AffinePoint<bigint>;

    constructor(public privateKey: bigint) {
        this.publicKey = p256.Point.BASE.multiply(privateKey).toAffine();
    }

    static randomScalar(): bigint {
        return mod(bytesToNumberBE(randomBytes(32)), p256.Point.Fn.ORDER);
    }

    static generate(): ECCKey { return new ECCKey(ECCKey.randomScalar()); }

    get publicBytes(): Uint8Array {
        return concatBytes(numberToBytesBE(this.publicKey.x, 32), numberToBytesBE(this.publicKey.y, 32));
    }

    public sign(data: Uint8Array | string): Uint8Array {
        if(typeof data == "string") data = new TextEncoder().encode(data);
        return p256.sign(data, numberToBytesBE(this.privateKey, 32));
    }

    public decrypt(ciphertext: Uint8Array): Uint8Array {
        const decrypted = ElGamal.decrypt(
            {
                point1: {
                    x: bytesToNumberBE(ciphertext.subarray(0,32)),
                    y: bytesToNumberBE(ciphertext.subarray(32,64))
                },
                point2: {
                    x: bytesToNumberBE(ciphertext.subarray(64,96)),
                    y: bytesToNumberBE(ciphertext.subarray(96,128))
                }
            },
            this.privateKey
        );

        return numberToBytesBE(decrypted.x, 32);
    }
}