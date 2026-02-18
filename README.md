<p align="center">
    <a href="https://github.com/li0ard/playready/">
        <img src="https://raw.githubusercontent.com/li0ard/playready/main/.github/logo.svg" alt="playready logo" title="playready" width="120" /><br>
    </a><br>
    <b>@li0ard/playready</b><br>
    <b>Simple PlayReady CDM implementation</b>
    <br>
    <a href="https://li0ard.is-cool.dev/playready">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/playready/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/playready" /></a>
    <a href="https://npmjs.com/package/@li0ard/playready"><img src="https://img.shields.io/npm/v/@li0ard/playready" />
    <br>
    <hr>
</p>

> [!CAUTION]
> - **Project doesn't provide encryption/signing key and group certificate for any purposes**
> - **Project doesn't condone piracy or any action against the terms of the DRM systems**
> - **Project is for study and research only. Please don't use it for commercial purposes**

## Features
- Support `.prd` deserialization
- Strictly typed API

## Installation

```bash
npm i @li0ard/playready
```

## Example

```ts
import { Device, CDM, KeyType, CipherType, PSSH } from "@li0ard/playready";

const device = Device.decode(
    Buffer.from("....", "base64"),
    Buffer.from("....", "base64"),
    Buffer.from("....", "base64")
); // Device.fromPrd(....);
const cdm = new CDM(device);

const pssh = PSSH.decode(Buffer.from("....", "base64"));
const challenge = cdm.getLicenseChallenge(pssh.decodedPayload as string);

const license = await (await fetch(`https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)`, {
    headers: {
        'Content-Type': 'text/xml; charset=UTF-8'
    },
    method: "POST",
    body: challenge
})).text();

for(const key of cdm.parseLicense(license))
    console.log(`- [${KeyType[key.type]}/${CipherType[key.cipher]}] ${key.kid.toHex()}:${key.key.toHex()}`);
```

## Links

- [PlayReady](https://microsoft.com/playready/) - PlayReady by Microsoft
- [pyplayready](https://git.gay/ready-dl/pyplayready) - An Open Source Python Implementation of PlayReady CDM (greatly inspired)