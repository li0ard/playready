import { CertificateChain } from "./certificate/index.js";
import { BinaryReader } from "./utils.js";

/** Device instance for CDM */
export class Device {
    /**
     * Device instance for CDM
     * @param encryption_key Encryption key
     * @param signing_key Signing key
     * @param group_certificate Group certificate
     * @param group_key Group key (optional)
     */
    constructor(
        public encryption_key: Uint8Array,
        public signing_key: Uint8Array,
        public group_certificate: Uint8Array,
        public group_key: Uint8Array = new Uint8Array(0)
    ) {}

    /** Decoded certificate chain */
    get chain(): CertificateChain {
        return new CertificateChain(new BinaryReader(this.group_certificate));
    }

    /** Get device instance from `.prd` file */
    static fromPrd(data: Uint8Array): Device {
        const rdr = new DataView(data.buffer);

        let offset = 0;
        const magic = new TextDecoder().decode(data.subarray(offset, offset += 3));
        if(magic != "PRD") throw new Error("Invalid magic constant, not a PRD file");

        const version = rdr.getUint8(offset);
        offset += 1;

        if(version == 3) {
            const group_key = data.slice(offset, offset += 96);
            const encryption_key = data.slice(offset, offset += 96);
            const signing_key = data.slice(offset, offset += 96);
            offset += 4;
                        
            return new Device(encryption_key, signing_key, data.slice(offset), group_key);
        }
        else if(version == 2) {
            const group_certificate_length = rdr.getUint32(offset);
            offset += 4;

            const group_certificate = data.slice(offset, offset += group_certificate_length);
            const encryption_key = data.slice(offset, offset += 96);
            const signing_key = data.slice(offset, offset += 96);

            return new Device(encryption_key, signing_key, group_certificate);
        }
        else throw new Error("Invalid PRD file");
    }
}