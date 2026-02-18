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
    x: 90785344306297710604867503975059265028223978614363440949957868233137570135451n,
    y: 68827801477692731286297993103001909218341737652466656881935707825713852622178n
}

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