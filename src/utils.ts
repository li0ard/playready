export class BinaryReader {
    public offset = 0;
    public length: number;
    private raw: Uint8Array;
    private rdr: DataView;

    constructor(data: Uint8Array) {
        this.offset = 0;
        this.length = data.length;
        this.raw = new Uint8Array(data);
        this.rdr = new DataView(data.buffer, data.byteOffset, data.byteLength);
    }

    getUint8(): number { return this.rdr.getUint8(this.offset++); }

    getUint16(): number {
        const result = this.rdr.getUint16(this.offset);
        this.offset += 2;
        return result;
    }

    getUint32(): number {
        const result = this.rdr.getUint32(this.offset);
        this.offset += 4;
        return result;
    }

    getBytes(size: number): Uint8Array {
        const result = this.raw.subarray(this.offset, this.offset + size);
        this.offset += size;
        return result;
    }
}

export const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

const CHARS = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/","="];
type B64 = typeof CHARS[number];
const B64IDX: Record<B64, number>={A:0,B:1,C:2,D:3,E:4,F:5,G:6,H:7,I:8,J:9,K:10,L:11,M:12,N:13,O:14,P:15,Q:16,R:17,S:18,T:19,U:20,V:21,W:22,X:23,Y:24,Z:25,a:26,b:27,c:28,d:29,e:30,f:31,g:32,h:33,i:34,j:35,k:36,l:37,m:38,n:39,o:40,p:41,q:42,r:43,s:44,t:45,u:46,v:47,w:48,x:49,y:50,z:51,0:52,1:53,2:54,3:55,4:56,5:57,6:58,7:59,8:60,9:61,"+":62,"/":63,"=":64};

export function bytesToBase64(input: Uint8Array): string {
    const inpLen = input.length;
    const inpRem = inpLen % 3;
    const padLen = inpRem > 0 ? 3 - inpRem : 0;
    const outLen = (inpLen + padLen) * 4 / 3;
    const output = new Array<string>(outLen);

    let j = 0;
    const len = inpLen - inpRem;
    for (let i = 2; i < len; i += 3) {
        const num24b = (input[i - 2] << 16) | (input[i - 1] << 8) | input[i];
        output[j++] = CHARS[(num24b >> 18) & 0x3f];
        output[j++] = CHARS[(num24b >> 12) & 0x3f];
        output[j++] = CHARS[(num24b >> 6) & 0x3f];
        output[j++] = CHARS[num24b & 0x3f];
    }

    if (padLen === 2) {
        const num24b = input[len] << 16;
        output[j++] = CHARS[(num24b >> 18) & 0x3f];
        output[j++] = CHARS[(num24b >> 12) & 0x3f];
        output[j++] = "=";
        output[j++] = "=";
    } else if (padLen === 1) {
        const num24b = (input[len] << 16) | (input[len + 1] << 8);
        output[j++] = CHARS[(num24b >> 18) & 0x3f];
        output[j++] = CHARS[(num24b >> 12) & 0x3f];
        output[j++] = CHARS[(num24b >> 6) & 0x3f];
        output[j++] = "=";
    }

    return output.join("");
}

export function base64ToBytes(strB64: string): Uint8Array {
    const input = strB64.split("") as B64[];
    const inpLen = input.length;
    const padLen = strB64.endsWith("==") ? 2 : strB64.endsWith("=") ? 1 : 0;
    const outLen = (inpLen * 3 / 4) - padLen;
    const output = new Uint8Array(outLen);

    let j = 0; // Output index
    const len = inpLen - (padLen > 0 ? 4 : 0);
    for (let i = 3; i < len; i += 4) {
        const num24b = (B64IDX[input[i - 3]] << 18) | (B64IDX[input[i - 2]] << 12) | (B64IDX[input[i - 1]] << 6) | B64IDX[input[i]];
        output[j++] = (num24b >> 16) & 0xff;
        output[j++] = (num24b >> 8) & 0xff;
        output[j++] = num24b & 0xff;
    }

    if (padLen === 2) {
        const num24b = (B64IDX[input[len]] << 18) | (B64IDX[input[len + 1]] << 12);
        output[j++] = (num24b >> 16) & 0xff;
    } else if (padLen === 1) {
        const num24b = (B64IDX[input[len]] << 18) | (B64IDX[input[len + 1]] << 12) | (B64IDX[input[len + 2]] << 6);
  
        output[j++] = (num24b >> 16) & 0xff;
        output[j++] = (num24b >> 8) & 0xff;
    }

    return output;
}