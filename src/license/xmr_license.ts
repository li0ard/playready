import { cmac } from "@noble/ciphers/aes.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import { BinaryReader } from "../utils.js";
import { AuxiliaryKeysObject, ContentKeyObject, SignatureObject, XMRLicenseObject, type XMRPayload } from "./structs.js";
import { LicenseContainer } from "../const.js";

export class XMRLicense {
    private object: XMRLicenseObject;

    constructor(private data: Uint8Array) {
        const reader = new BinaryReader(new Uint8Array(data));
        this.object = new XMRLicenseObject(reader);
    }

    public getByType(type: number): XMRPayload[] { return this.object.containers.filter(i => i.type === type); }

    get isScalable(): boolean {
        return this.getByType(LicenseContainer.AUX_KEY_OBJECT).length > 0;
    }

    get contentKeys(): ContentKeyObject[] {
        return this.getByType(LicenseContainer.CONTENT_KEY_OBJECT).map(i => i.data as ContentKeyObject);
    }

    get auxiliaryKeys(): AuxiliaryKeysObject[] {
        return this.getByType(LicenseContainer.AUX_KEY_OBJECT).map(i => i.data as AuxiliaryKeysObject);
    }

    public verify(key: Uint8Array): boolean {
        const signatureObject = this.getByType(11)[0].data as SignatureObject;
        const raw_data = this.data;

        return equalBytes(
            cmac(key, raw_data.subarray(0, raw_data.length - (signatureObject.length + 12))),
            signatureObject.data
        );
    }
}