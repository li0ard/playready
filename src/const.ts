import type { AffinePoint } from "@noble/curves/abstract/curve.js";

export enum LicenseContainer {
    CONTENT_KEY_OBJECT = 10,
    SIGNATURE_OBJECT = 11,
    AUX_KEY_OBJECT = 81
}

/** Key type */
export enum KeyType {
    INVALID = 0,
    AES_128_CTR,
    RC4_CIPHER,
    AES_128_ECB,
    COCKTAIL,
    AES_128_CBC,
    KEYEXCHANGE,
    UNKNOWN = 0xffff,
}

/** Cipher type */
export enum CipherType {
    INVALID = 0,
    RSA_1024,
    CHAINED_LICENSE,
    ECC_256,
    ECC_256_WITH_KZ,
    TEE_TRANSIENT,
    ECC_256_VIA_SYMMETRIC,
    UNKNOWN = 0xffff
}

export const WMRM_SERVER_KEY: Readonly<AffinePoint<bigint>> = {
    x: 0xc8b6af16ee941aadaa5389b4af2c10e356be42af175ef3face93254e7b0b3d9bn,
    y: 0x982b27b5cb2341326e56aa857dbfd5c634ce2cf9ea74fca8f2af5957efeea562n
}

export const MSPR_ROOT_PUBLIC_KEY: Readonly<Uint8Array> = new Uint8Array([
    0x86, 0x4D, 0x61, 0xCF, 0xF2, 0x25, 0x6E, 0x42, 0x2C, 0x56, 0x8B, 0x3C, 0x28, 0x00, 0x1C, 0xFB,
    0x3E, 0x15, 0x27, 0x65, 0x85, 0x84, 0xBA, 0x05, 0x21, 0xB7, 0x9B, 0x18, 0x28, 0xD9, 0x36, 0xDE,
    0x1D, 0x82, 0x6A, 0x8F, 0xC3, 0xE6, 0xE7, 0xFA, 0x7A, 0x90, 0xD5, 0xCA, 0x29, 0x46, 0xF1, 0xF6,
    0x4A, 0x2E, 0xFB, 0x9F, 0x5D, 0xCF, 0xFE, 0x7E, 0x43, 0x4E, 0xB4, 0x42, 0x93, 0xFA, 0xC5, 0xAB
]);

export const RGB_MAGIC: Readonly<Uint8Array> = new Uint8Array([0x7e, 0xe9, 0xed, 0x4a, 0xf7, 0x73, 0x22, 0x4f, 0x00, 0xb8, 0xea, 0x7e, 0xfb, 0x02, 0x7c, 0xbb]);

// Templates

export const SIGNEDINFO_TEMP = (
    `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
        `<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>` +
        `<SignatureMethod Algorithm="http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256"></SignatureMethod>` +
        `<Reference URI="#SignedData">` +
            `<DigestMethod Algorithm="http://schemas.microsoft.com/DRM/2007/03/protocols#sha256"></DigestMethod>` +
            `<DigestValue>{digest_value}</DigestValue>` +
        `</Reference>` +
    `</SignedInfo>`
);

export const LA_TEMP = (
    `<LA xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols" Id="SignedData" xml:space="preserve">` +
        `<Version>{protocol_version}</Version>` +
        `<ContentHeader>{content_header}</ContentHeader>` +
        `<CLIENTINFO>` +
            `<CLIENTVERSION>{client_version}</CLIENTVERSION>` +
        `</CLIENTINFO>{rev_lists}` +
        `<LicenseNonce>{nonce}</LicenseNonce>` +
        `<ClientTime>{clientTime}</ClientTime>` +
        `<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
            `<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>` +
            `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
                `<EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">` +
                    `<EncryptionMethod Algorithm="http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256"></EncryptionMethod>` +
                    `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
                        `<KeyName>WMRMServer</KeyName>` +
                    `</KeyInfo>` +
                    `<CipherData>` +
                        `<CipherValue>{key_cipher}</CipherValue>` +
                    `</CipherData>` +
                `</EncryptedKey>` +
            `</KeyInfo>` +
            `<CipherData>` +
                `<CipherValue>{data_cipher}</CipherValue>` +
            `</CipherData>` +
        `</EncryptedData>` +
    `</LA>`
);

export const SOAP_TEMP = (
    '<?xml version="1.0" encoding="utf-8"?>' +
    '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<soap:Body>' +
        '<AcquireLicense xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols">' +
            '<challenge>' +
                '<Challenge xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols/messages">' +
                    '{la_content}<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
                        `{signed_info}<SignatureValue>{signature_value}</SignatureValue>` +
                        '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
                            '<KeyValue>' +
                                '<ECCKeyValue>' +
                                    `<PublicKey>{public_key}</PublicKey>` +
                                '</ECCKeyValue>' +
                            '</KeyValue>' +
                        '</KeyInfo>' +
                    '</Signature>' +
                '</Challenge>' +
            '</challenge>' +
        '</AcquireLicense>' +
    '</soap:Body>' +
    '</soap:Envelope>'
);