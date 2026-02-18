import { CipherType } from "../const.js";
import type { BinaryReader } from "../utils.js";

export class SignatureObject {
    public type: number;
    public length: number;
    public data: Uint8Array;

    constructor(reader: BinaryReader) {
        this.type = reader.getUint16();
        this.length = reader.getUint16();
        this.data = reader.getBytes(this.length);
    }
}

export class AuxiliaryKey {
    public location: number;
    public key: Uint8Array;

    constructor(reader: BinaryReader) {
        this.location = reader.getUint32();
        this.key = reader.getBytes(16);
    }
}

export class AuxiliaryKeysObject {
    public count: number;
    public auxiliary_keys: AuxiliaryKey[] = [];

    constructor(reader: BinaryReader) {
        this.count = reader.getUint16();
        for (let _ = 0; _ < this.count; _++) this.auxiliary_keys.push(new AuxiliaryKey(reader));
    }
}

export class ContentKeyObject {
    public kid: Uint8Array;
    public type: number;
    public cipher: number;
    public encrypted_key: Uint8Array;

    constructor(reader: BinaryReader) {
        this.kid = reader.getBytes(16);
        this.type = reader.getUint16();
        this.cipher = reader.getUint16();
        this.encrypted_key = reader.getBytes(reader.getUint16());
    }

    get viaSymmetric(): boolean {
        return this.cipher == CipherType.ECC_256_VIA_SYMMETRIC;
    }
}

export class XMRPayload {
    public flags: number;
    public type: number;
    public length: number;
    public data: ContentKeyObject | SignatureObject | AuxiliaryKeysObject | Uint8Array | null = null;

    constructor(reader: BinaryReader) {
        this.flags = reader.getUint16();
        this.type = reader.getUint16();
        this.length = reader.getUint32();
        this.data = null;
        if (this.flags === 0 || this.flags === 1) {
            switch (this.type) {
                case 10:
                    this.data = new ContentKeyObject(reader);
                    break;
                case 11:
                    this.data = new SignatureObject(reader);
                    break;
                case 81:
                    this.data = new AuxiliaryKeysObject(reader);
                    break;
                default:
                    this.data = reader.getBytes(this.length - 8);
            }
        }
    }
}

export class XMRLicenseObject {
    public signature: Uint8Array;
    public xmr_version: number;
    public rights_id: Uint8Array;
    public containers: XMRPayload[];

    constructor(reader: BinaryReader) {
        this.signature = reader.getBytes(4);
        this.xmr_version = reader.getUint32();
        this.rights_id = reader.getBytes(16);
        this.containers = [];

        while (reader.length > reader.offset) this.containers.push(new XMRPayload(reader));
    }
}