import { bytesToHex } from "@noble/ciphers/utils.js";
import type { BinaryReader } from "../utils.js";

export enum CertCertType {
    UNKNOWN,
    PC,
    DEVICE,
    DOMAIN,
    ISSUER,
    CRL_SIGNER,
    SERVICE,
    SILVERLIGHT,
    APPLICATION,
    METERING,
    KEYFILESIGNER,
    SERVER,
    LICENSESIGNER,
    SECURETIMESERVER,
    RPROVMODELAUTH,
}

export enum CertObjType {
    BASIC = 1,
    DOMAIN,
    PC,
    DEVICE,
    FEATURE,
    KEY,
    MANUFACTURER,
    SIGNATURE,
    SILVERLIGHT,
    METERING,
    EXTDATASIGNKEY,
    EXTDATACONTAINER,
    EXTDATASIGNATURE,
    EXTDATA_HWID,
    SERVER,
    SECURITY_VERSION,
    SECURITY_VERSION_2,
    UNKNOWN_OBJECT_ID = 0xFFFD
}

enum CertFlag {
    EMPTY,
    EXTDATA_PRESENT
}

enum CertObjFlag {
    EMPTY,
    MUST_UNDERSTAND,
    CONTAINER_OBJ
}

export enum CertSignatureType {
    P256 = 1
}

export enum CertKeyType {
    ECC256 = 1
}

export enum CertKeyUsage {
    UNKNOWN,
    SIGN,
    ENCRYPT_KEY,
    SIGN_CRL,
    ISSUER_ALL,
    ISSUER_INDIV,
    ISSUER_DEVICE,
    ISSUER_LINK,
    ISSUER_DOMAIN,
    ISSUER_SILVERLIGHT,
    ISSUER_APPLICATION,
    ISSUER_CRL,
    ISSUER_METERING,
    ISSUER_SIGN_KEYFILE,
    SIGN_KEYFILE,
    ISSUER_SERVER,
    ENCRYPTKEY_SAMPLE_PROTECTION_RC4,
    RESERVED2,
    ISSUER_SIGN_LICENSE,
    SIGN_LICENSE,
    SIGN_RESPONSE,
    PRND_ENCRYPT_KEY_DEPRECATED,
    ENCRYPTKEY_SAMPLE_PROTECTION_AES128CTR,
    ISSUER_SECURETIMESERVER,
    ISSUER_RPROVMODELAUTH
}

export enum CertFeatures {
    TRANSMITTER = 1,
    RECEIVER,
    SHARED_CERTIFICATE,
    SECURE_CLOCK,
    ANTIROLLBACK_CLOCK,
    RESERVED_METERING,
    RESERVED_LICSYNC,
    RESERVED_SYMOPT,
    SUPPORTS_CRLS,
    SERVER_BASIC_EDITION,
    SERVER_STANDARD_EDITION,
    SERVER_PREMIUM_EDITION,
    SUPPORTS_PR3_FEATURES,
    DEPRECATED_SECURE_STOP
}

export class Header {
    public flags: number;
    public tag: number;
    public length: number;

    constructor(data: BinaryReader) {
        this.flags = data.getUint16();
        this.tag = data.getUint16();
        this.length = data.getUint32();
    }
}

export class BasicInfo {
    public cert_id: Uint8Array;
    public security_level: number;
    public flags: number;
    public cert_type: number;
    public public_key_digest: Uint8Array;
    public expiration_date: number;
    public client_id: Uint8Array;

    constructor(data: BinaryReader) {
        this.cert_id = data.getBytes(16);
        this.security_level = data.getUint32();
        this.flags = data.getUint32();
        this.cert_type = data.getUint32();
        this.public_key_digest = data.getBytes(32);
        this.expiration_date = data.getUint32();
        this.client_id = data.getBytes(16);
    }
}

export class DomainInfo {
    public service_id: Uint8Array;
    public account_id: Uint8Array;
    public revision_timestamp: number;
    public domain_url_length: number;
    public domain_url: Uint8Array;

    constructor(data: BinaryReader) {
        this.service_id = data.getBytes(16);
        this.account_id = data.getBytes(16);
        this.revision_timestamp = data.getUint32();
        this.domain_url_length = data.getUint32();
        this.domain_url = data.getBytes((this.domain_url_length + 3) & 0xfffffffc);
    }
}

export class PCInfo {
    public security_version: number;

    constructor(data: BinaryReader) {
        this.security_version = data.getUint32();
    }
}

export class DeviceInfo {
    public max_license: number;
    public max_header: number;
    public max_chain_depth: number;

    constructor(data: BinaryReader) {
        this.max_license = data.getUint32();
        this.max_header = data.getUint32();
        this.max_chain_depth = data.getUint32();
    }

    toString() {
        return `DeviceInfo(max_license=${this.max_license}, max_header=${this.max_header}, max_chain_depth=${this.max_chain_depth})`;
    }
}

export class FeatureInfo {
    public feature_count: number;
    public features: CertFeatures[];

    constructor(data: BinaryReader) {
        this.feature_count = data.getUint32();
        
        this.features = [];
        for (let i = 0; i < this.feature_count; i++) this.features.push(data.getUint32());
    }

    toString() {
        return `FeatureInfo(features=${this.features.map(i => CertFeatures[i]).join(", ")})`;
    }
}

export class CertKey {
    public type: CertKeyType;
    public length: number;
    public flags: number;
    public key: Uint8Array;
    public usages_count: number;
    public usages: CertKeyUsage[];

    constructor(data: BinaryReader) {
        this.type = data.getUint16();
        this.length = data.getUint16();
        this.flags = data.getUint32();
        this.key = data.getBytes((this.length / 8) | 0);
        this.usages_count = data.getUint32();

        this.usages = [];
        for (let i = 0; i < this.usages_count; i++) this.usages.push(data.getUint32());
    }

    toString() {
        return `CertKey<${bytesToHex(this.key)}>(type=${CertKeyType[this.type]}, usages=${this.usages.map(i => CertKeyUsage[i]).join(", ")})`;
    }
}

export class KeyInfo {
    public key_count: number;
    public cert_keys: CertKey[];

    constructor(data: BinaryReader) {
        this.key_count = data.getUint32();
        this.cert_keys = [];
        for (let i = 0; i < this.key_count; i++) this.cert_keys.push(new CertKey(data));
    }
}

export class ManufacturerInfo {
    public flags: number;
    public manufacturer_name_length: number;
    public manufacturer_name: string;
    public model_name_length: number;
    public model_name: string;
    public model_number_length: number;
    public model_number: string;

    constructor(data: BinaryReader) {
        this.flags = data.getUint32();
        this.manufacturer_name_length = data.getUint32();
        this.manufacturer_name = new TextDecoder().decode(data.getBytes((this.manufacturer_name_length + 3) & 0xfffffffc)).replaceAll("\x00", "");
        this.model_name_length = data.getUint32();
        this.model_name = new TextDecoder().decode(data.getBytes((this.model_name_length + 3) & 0xfffffffc)).replaceAll("\x00", "");
        this.model_number_length = data.getUint32();
        this.model_number = new TextDecoder().decode(data.getBytes((this.model_number_length + 3) & 0xfffffffc)).replaceAll("\x00", "");
    }
}

export class SignatureInfo {
    public signature_type: CertSignatureType;
    public signature_size: number;
    public signature: Uint8Array;
    public signature_key_size: number;
    public signature_key: Uint8Array;

    constructor(data: BinaryReader) {
        this.signature_type = data.getUint16();
        this.signature_size = data.getUint16();
        this.signature = data.getBytes(this.signature_size);
        this.signature_key_size = data.getUint32();
        this.signature_key = data.getBytes((this.signature_key_size / 8) | 0);
    }
}

export class SilverlightInfo {
    public security_version: number;
    public platform_identifier: number;

    constructor(data: BinaryReader) {
        this.security_version = data.getUint32();
        this.platform_identifier = data.getUint32();
    }
}

export class MeteringInfo {
    public metering_id: Uint8Array;
    public metering_url_length: number;
    public metering_url: Uint8Array;

    constructor(data: BinaryReader) {
        this.metering_id = data.getBytes(16);
        this.metering_url_length = data.getUint32();
        this.metering_url = data.getBytes((this.metering_url_length + 3) & 0xfffffffc);
    }
}

export class ExtDataSignKeyInfo {
    public key_type: number;
    public key_length: number;
    public flags: number;
    public key: Uint8Array;

    constructor(data: BinaryReader) {
        this.key_type = data.getUint16();
        this.key_length = data.getUint16();
        this.flags = data.getUint32();
        this.key = data.getBytes((this.key_length / 8) | 0)
    }
}

class DataRecord {
    public data_size: number;
    public data: Uint8Array;

    constructor(data: BinaryReader) {
        this.data_size = data.getUint32();
        this.data = data.getBytes(this.data_size);
    }
}

export class ExtDataSignature {
    public signature_type: number;
    public signature_size: number;
    public signature: Uint8Array;

    constructor(data: BinaryReader) {
        this.signature_type = data.getUint32();
        this.signature_size = data.getUint32();
        this.signature = data.getBytes(this.signature_size);
    }
}

export class ExtDataHwid {
    public record_length: number;
    public record_data: Uint8Array;
    public padding: Uint8Array;

    constructor(data: BinaryReader) {
        this.record_length = data.getUint32();
        this.record_data = data.getBytes(this.record_length);
        this.padding = data.getBytes((4 - (this.record_length % 4)) % 4);
    }
}

export class ExtDataContainer {
    public record: {
        header: Header;
        hwid: ExtDataHwid;
    }
    public signature: {
        header: Header;
        signature: ExtDataSignature;
    }

    constructor(data: BinaryReader) {
        this.record = {
            header: new Header(data),
            hwid: new ExtDataHwid(data)
        }
        
        this.signature = {
            header: new Header(data),
            signature: new ExtDataSignature(data)
        }
    }
}

export class ServerInfo {
    public warning_days: number;

    constructor(data: BinaryReader) {
        this.warning_days = data.getUint32();
    }
}

export class SecurityVersion {
    public security_version: number;
    public platform_identifier: number;

    constructor(data: BinaryReader) {
        this.security_version = data.getUint32();
        this.platform_identifier = data.getUint32();
    }
}

export class Attribute {
    public header: Header;
    public attribute: unknown;

    constructor(data: BinaryReader) {
        this.header = new Header(data);

        switch(this.header.tag) {
            case CertObjType.BASIC:
                this.attribute = new BasicInfo(data);
            break;
            case CertObjType.DOMAIN:
                this.attribute = new DomainInfo(data);
            break;
            case CertObjType.PC:
                this.attribute = new PCInfo(data);
            break;
            case CertObjType.DEVICE:
                this.attribute = new DeviceInfo(data);
            break;
            case CertObjType.FEATURE:
                this.attribute = new FeatureInfo(data);
            break;
            case CertObjType.KEY:
                this.attribute = new KeyInfo(data);
            break;
            case CertObjType.MANUFACTURER:
                this.attribute = new ManufacturerInfo(data);
            break;
            case CertObjType.SIGNATURE:
                this.attribute = new SignatureInfo(data);
            break;
            case CertObjType.SILVERLIGHT:
                this.attribute = new SilverlightInfo(data);
            break;
            case CertObjType.METERING:
                this.attribute = new MeteringInfo(data);
            break;
            case CertObjType.EXTDATASIGNKEY:
                this.attribute = new ExtDataSignKeyInfo(data);
            break;
            case CertObjType.EXTDATACONTAINER:
                this.attribute = new ExtDataContainer(data);
            break;
            /*case CertObjType.EXTDATASIGNATURE:
                this.attribute = new ExtDataSignature(data);
            break;
            case CertObjType.EXTDATA_HWID:
                this.attribute = new ExtDataHwid(data);
            break;*/
            case CertObjType.SERVER:
                this.attribute = new ServerInfo(data);
            break;
            case CertObjType.SECURITY_VERSION:
                this.attribute = new SecurityVersion(data);
            break;
            case CertObjType.SECURITY_VERSION_2:
                this.attribute = new SecurityVersion(data);
            break;
            default:
                this.attribute = data.getBytes(this.header.length - 8);
            break;
        }
    }
}