import { bytesToNumberBE, randomBytes } from "@noble/curves/utils.js";
import { ECCKey, XMLKey } from "./crypto/index.js";
import { Device } from "./device.js";
import { ecb } from "@noble/ciphers/aes.js";
import { parse as parseDOM } from "node-html-parser";
import { sha256 } from "@noble/hashes/sha2.js";
import { XMRLicense } from "./license/xmr_license.js";
import { xor, base64ToBytes, bytesToBase64 } from "./utils.js";
import { Key } from "./key.js";
import { CipherType, ENCRYPTED_CHAIN_TEMP, LA_TEMP, RGB_MAGIC, SIGNEDINFO_TEMP, SOAP_TEMP } from "./const.js";

/** PlayReady Content Decryption Module (CDM) instance */
export class CDM {
    private certificate_chain: Uint8Array;
    private encryption_key: ECCKey;
    private signing_key: ECCKey;

    /**
     * PlayReady Content Decryption Module (CDM) instance
     * @param device Device instance
     */
    constructor(device: Device) {
        this.certificate_chain = device.group_certificate;
        this.encryption_key = new ECCKey(bytesToNumberBE(device.encryption_key.subarray(0,32)));
        this.signing_key = new ECCKey(bytesToNumberBE(device.signing_key.subarray(0,32)));
    }

    /**
     * Get license request (challenge)
     * @param wrmHeader WRM Header
     * @param revLists Revocation lists
     * @param clientVersion Client version
     */
    public getLicenseChallenge(wrmHeader: string, revLists: string = "", clientVersion = "10.0.16384.10011"): string {
        if(!wrmHeader.includes("WRMHEADER")) throw new Error("Invalid WRM header");
        const xmlkey = new XMLKey();
        const wrmHeaderVersion = parseDOM(wrmHeader).getAttribute("version");

        let protocol_version = 1;
        switch (wrmHeaderVersion){
            case "4.3.0.0":
                protocol_version = 5;
                break;
            case "4.2.0.0":
                protocol_version = 4;
                break;
        }

        const clientTime = Math.floor(Date.now() / 1000);
        const encryptedChain = xmlkey.encrypt(ENCRYPTED_CHAIN_TEMP.replace("{certificate_chain}", bytesToBase64(this.certificate_chain)));
        const laContent = LA_TEMP
            .replace("{protocol_version}", protocol_version.toString())
            .replace("{content_header}", wrmHeader)
            .replace("{client_version}", clientVersion)
            .replace("{rev_lists}", revLists)
            .replace("{nonce}", bytesToBase64(randomBytes(16)))
            .replace("{clientTime}", clientTime.toString())
            .replace("{key_cipher}", bytesToBase64(xmlkey.encryptedWithWMRM))
            .replace("{data_cipher}", bytesToBase64(encryptedChain));

        const signedInfo = SIGNEDINFO_TEMP
            .replace("{digest_value}", bytesToBase64(sha256(new TextEncoder().encode(laContent))));

        return SOAP_TEMP
            .replace("{la_content}", laContent)
            .replace("{signed_info}", signedInfo)
            .replace("{signature_value}", bytesToBase64(this.signing_key.sign(signedInfo)))
            .replace("{public_key}", bytesToBase64(this.signing_key.publicBytes));
    }

    /**
     * Get keys from license response
     * @param license License response
     */
    public parseLicense(license: string): Key[] {
        const xmlDoc = parseDOM(license);

        const keys = [];
        for(const licenseElement of xmlDoc.getElementsByTagName("License")) {
            const xmrLicense = new XMRLicense(base64ToBytes(licenseElement.textContent));

            for(const contentKeyObject of xmrLicense.contentKeys) {
                if (![CipherType.ECC_256, CipherType.ECC_256_WITH_KZ, CipherType.ECC_256_VIA_SYMMETRIC].includes(contentKeyObject.cipher)) continue;

                const encryptedKey = contentKeyObject.encrypted_key;
                const decrypted = this.encryption_key.decrypt(encryptedKey);

                let ci: Uint8Array = decrypted.slice(0, 16), ck: Uint8Array = decrypted.slice(16, 32);
                if(xmrLicense.isScalable) {
                    ci = decrypted.filter((_, index) => index % 2 === 0).slice(0,16);
                    ck = decrypted.filter((_, index) => index % 2 === 1).slice(0,16);

                    if (contentKeyObject.viaSymmetric) {
                        const embeddedRootLicense = encryptedKey.slice(0, 144);
                        let embeddedLeafLicense: Uint8Array = encryptedKey.slice(144);

                        const rgbKey = xor(ck, RGB_MAGIC);
                        const contentKeyPrime = ecb(ck).encrypt(rgbKey);

                        const auxKey = xmrLicense.auxiliaryKeys[0].auxiliary_keys[0].key;
                        const uplinkXKey = ecb(contentKeyPrime).encrypt(auxKey);
                        const secondaryKey = ecb(ck).encrypt(embeddedRootLicense.subarray(128));

                        embeddedLeafLicense = ecb(uplinkXKey).encrypt(embeddedLeafLicense);
                        embeddedLeafLicense = ecb(secondaryKey).encrypt(embeddedLeafLicense);

                        ci = embeddedLeafLicense.subarray(0,16);
                        ck = embeddedLeafLicense.subarray(16,32);
                    }
                }

                if (!xmrLicense.verify(ci)) throw new Error("Signature mismatch in license");

                keys.push(new Key(contentKeyObject.kid, contentKeyObject.type, contentKeyObject.cipher, ck));
            }
        }

        return keys;
    }
}

export { Device } from "./device.js";
export { Key } from "./key.js";
export { KeyType, CipherType } from "./const.js";
export { PSSH } from "@li0ard/pssh";