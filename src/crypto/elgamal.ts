import type { AffinePoint } from "@noble/curves/abstract/curve.js";
import { p256 } from "@noble/curves/nist.js";
import { ECCKey } from "./ecckey.js";

interface EncryptedMessage {
    point1: AffinePoint<bigint>;
    point2: AffinePoint<bigint>;
}

export class ElGamal {
    static encrypt(message: AffinePoint<bigint>, publicKey: AffinePoint<bigint>): EncryptedMessage {
        const messagePoint = p256.Point.fromAffine(message);
        messagePoint.assertValidity();
        const publicKeyPoint = p256.Point.fromAffine(publicKey);
        const ephemeralKey = ECCKey.randomScalar();

        return {
            point1: p256.Point.BASE.multiply(ephemeralKey).toAffine(),
            point2: messagePoint.add(publicKeyPoint.multiply(ephemeralKey)).toAffine()
        }
    }

    static decrypt({ point1, point2 }: EncryptedMessage, privateKey: bigint): AffinePoint<bigint> {
        const p1 = p256.Point.fromAffine(point1);
        p1.assertValidity();
        const p2 = p256.Point.fromAffine(point2);
        p2.assertValidity();

        return p2.subtract(p1.multiply(privateKey)).toAffine();
    }
}