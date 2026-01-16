import AESScheme from "./AES/AESScheme";
import Ed25519Scheme from "./Ed25519/Ed25519Scheme";
export declare const SchemeType: (typeof AESScheme | typeof Ed25519Scheme)[];
