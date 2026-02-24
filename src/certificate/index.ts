import { bytesToHex, bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { ECCKey } from "../crypto/index.js";
import type { BinaryReader } from "../utils.js";
import { p256 } from "@noble/curves/nist.js";
import { MSPR_ROOT_PUBLIC_KEY } from "../const.js";
import { Attribute, type BasicInfo, type ManufacturerInfo, type SignatureInfo, type KeyInfo, type DeviceInfo, type FeatureInfo, CertObjType, CertCertType, CertKeyUsage, CertKeyType, CertFeatures } from "./structs.js";

class Certificate {
    public signature: string;
    public version: number;
    public total_length: number;
    public certificate_length: number;
    public attributes: Attribute[];
    private raw: Uint8Array;

    constructor(data: BinaryReader) {
        const startOffset = data.offset;

        this.signature = new TextDecoder().decode(data.getBytes(4));
        this.version = data.getUint32();
        this.total_length = data.getUint32();
        this.certificate_length = data.getUint32();

        const attrStartPos = data.offset;
        this.attributes = [];
        while (data.offset - attrStartPos < this.certificate_length && data.hasRemaining()) {
            if (data.offset >= startOffset + this.total_length) break;
            this.attributes.push(new Attribute(data));
        }
        
        const bytesToSkip = (startOffset + this.total_length) - data.offset;
        if (bytesToSkip > 0) data.offset += bytesToSkip;

        const endOffset = data.offset;
        this.raw = data.slice(startOffset, endOffset);
    }

    getAttribute(type: CertObjType): Attribute | null {
        return this.attributes.find(i => i.header.tag == type) ?? null;
    }

    get security_level(): number | null {
        const basic_info = this.getAttribute(CertObjType.BASIC);
        if(basic_info) return (basic_info.attribute as BasicInfo).security_level;

        return null;
    }

    get name(): string | null {
        const manufacturer_info_attr = this.getAttribute(CertObjType.MANUFACTURER);
        if(manufacturer_info_attr) {
            const manufacturer_info = manufacturer_info_attr.attribute as ManufacturerInfo;

            return `${manufacturer_info.manufacturer_name} ${manufacturer_info.model_name} ${manufacturer_info.model_number}`;
        }

        return null;
    }

    get type(): CertCertType | null {
        const basic_info = this.getAttribute(CertObjType.BASIC);
        if(basic_info) return (basic_info.attribute as BasicInfo).cert_type;

        return null;
    }

    get expiration_date(): number | null {
        const basic_info = this.getAttribute(CertObjType.BASIC);
        if(basic_info) return (basic_info.attribute as BasicInfo).expiration_date;

        return null;
    }

    get issuer_key(): Uint8Array | null {
        const signature_object = this.getAttribute(CertObjType.SIGNATURE);
        if(!signature_object) return null;

        return (signature_object.attribute as SignatureInfo).signature_key;
    }

    get_key_by_usage(key_usage: CertKeyUsage): Uint8Array | null {
        const key_info_object = this.getAttribute(CertObjType.KEY)?.attribute as KeyInfo | undefined;
        if (!key_info_object) return null;

        const foundKey = key_info_object.cert_keys.find(key => key.usages?.includes(key_usage));

        return foundKey?.key ?? null;
    }

    contains_public_key(public_key: ECCKey | Uint8Array): boolean {
        if(public_key instanceof ECCKey) public_key = public_key.publicBytes;

        const key_info_object = this.getAttribute(CertObjType.KEY);
        if(!key_info_object) return false;

        return (key_info_object.attribute as KeyInfo).cert_keys.some(i => equalBytes(i.key, public_key));
    }

    verify(): boolean {
        const signature_attribute = this.getAttribute(CertObjType.SIGNATURE)?.attribute as SignatureInfo;
        if(!signature_attribute) throw new Error("No signature found in certificate");

        const raw_signature_key = signature_attribute.signature_key;
        const signature_key = p256.Point.fromAffine({
            x: bytesToNumberBE(raw_signature_key.subarray(0,32)),
            y: bytesToNumberBE(raw_signature_key.subarray(32))
        });
        signature_key.assertValidity();

        return p256.verify(signature_attribute.signature, this.raw.subarray(0, this.certificate_length), signature_key.toBytes(), {
            lowS: false
        });
    }

    toString(): string {
        let str = `Certificate<${this.type ? CertCertType[this.type] : "-"}/${this.security_level}>(${this.name}, exp=${this.expiration_date}, iss=${this.issuer_key ? bytesToHex(this.issuer_key) : "-"}`;

        const device = this.getAttribute(CertObjType.DEVICE)?.attribute as DeviceInfo | undefined;
        if(device) str += `, deviceInfo=${device.toString()}`;

        const keys = this.getAttribute(CertObjType.KEY)?.attribute as KeyInfo | undefined;
        if(keys) str += `, keys=[${keys.cert_keys.map(i => i.toString())}]`;

        const features = this.getAttribute(CertObjType.FEATURE)?.attribute as FeatureInfo | undefined;
        if(features && features.feature_count != 0) str += `, features=${features.toString()}`;

        if(this.getAttribute(CertObjType.SIGNATURE)) str += `, signature=${this.verify() ? "OK" : "ERR"}`;

        str += ")";
        return str;
    }
}

/** Certificates chain */
export class CertificateChain {
    public signature: string;
    public version: number;
    public total_length: number;
    public flags: number;
    public certificate_count: number;
    public certificates: Certificate[];

    constructor(data: BinaryReader) {
        this.signature = new TextDecoder().decode(data.getBytes(4));
        this.version = data.getUint32();
        this.total_length = data.getUint32();
        this.flags = data.getUint32();
        this.certificate_count = data.getUint32();

        this.certificates = [];
        for(let i = 0; i < this.certificate_count; i++) this.certificates.push(new Certificate(data));
        /*const startPos = data.offset;
        while (data.hasRemaining()) {
            if (data.offset - startPos >= this.total_length - 20) break;
            if (data.offset + 16 > data.length) break;

            try { this.certificates.push(new BCert(data)); }
            catch (e) { break; }
        }*/
    }

    /** Verify chain */
    verify(expiry = false) {
        if(this.certificate_count < 1 || this.certificate_count > 6) throw new Error("Invalid chain depth");

        for(let i = 0; i < this.certificate_count; i++) {
            const certificate = this.certificates[i];

            if(!certificate.verify()) return false;
            if(expiry && certificate.expiration_date && ((Date.now() / 1000) | 0) > certificate.expiration_date) return false;
            if(i == this.certificate_count - 1 && certificate.issuer_key && !equalBytes(certificate.issuer_key, MSPR_ROOT_PUBLIC_KEY)) return false;
        }

        return true;
    }
}