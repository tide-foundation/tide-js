import { Serialization } from "../Cryptide/index.js";
import { CreateTideMemory, WriteValue, GetValue } from "../Cryptide/Serialization.js";

export class AdminAuthorization {
    constructor(...args) {
        if (typeof args[0] === 'string') {
            const [adminContextStr, adminCertStr, authMsgStr, blindSigStr, approvalSigStr] = args;
            this.adminContext = JSON.parse(adminContextStr);
            this.adminCertificate = Serialization.base64ToBytes(adminCertStr);
            this.adminTideAuthMsg = authMsgStr;
            this.blindSig = Serialization.base64ToBytes(blindSigStr);
            this.approvalSig = Serialization.base64ToBytes(approvalSigStr);
        } else {
            const [adminContextBytes, adminCertBytes, authMsgBytes, blindSigBytes, approvalSigBytes] = args;
            const contextStr = new TextDecoder().decode(adminContextBytes);
            const authMsgStr = new TextDecoder().decode(authMsgBytes);
            this.adminContext = JSON.parse(contextStr);
            this.adminCertificate = adminCertBytes;
            this.adminTideAuthMsg = authMsgStr;
            this.blindSig = blindSigBytes;
            this.approvalSig = approvalSigBytes;
        }

        this.EncodedApproval = null;
    }

    compareInitCertHash(initCertHash) {
        const myHash = this.getInitCertHash();
        return arrayEquals(myHash, initCertHash);
    }

    getInitCertHash() {
        // Implement your own logic for creating a hash from this.adminContext
        // Placeholder: return SHA-256 hash of stringified context
        const contextStr = JSON.stringify(this.adminContext);
        return sha256(contextStr); // You must define this (or use SubtleCrypto)
    }

    encodeContext() {
        const contextStr = JSON.stringify(this.adminContext);
        return new TextEncoder().encode(contextStr);
    }

    getAdminCert() {
        return this.adminCertificate;
    }

    encodeApproval() {
        if (!this.EncodedApproval) {
            const authMsgBytes = new TextEncoder().encode(this.adminTideAuthMsg);
            const totalLength = 4 + 4 + 4 + authMsgBytes.length + this.blindSig.length + this.approvalSig.length;
            const d = CreateTideMemory(authMsgBytes, totalLength);
            WriteValue(d, 1, this.blindSig);
            WriteValue(d, 2, this.approvalSig);
            this.EncodedApproval = d;
        }
        return this.EncodedApproval;
    }

    toString() {
        const ac = this.encodeContext();
        const am = new TextEncoder().encode(this.adminTideAuthMsg);
        const totalLength = (6 * 5) + ac.length + am.length + this.adminCertificate.length + this.blindSig.length + this.approvalSig.length;
        const d = Tools.createTideMemory(ac, totalLength);
        WriteValue(d, 1, am);
        WriteValue(d, 2, this.adminCertificate);
        WriteValue(d, 3, this.blindSig);
        WriteValue(d, 4, this.approvalSig);
        return encodeBase64Url(d);
    }

    static fromString(s) {
        const d = Serialization.base64ToBytes(Serialization.base64UrlToBase64(s));
        const adminContext = GetValue(d, 0);
        const adminAuthMessage = GetValue(d, 1);
        const adminCert = GetValue(d, 2);
        const blindSig = GetValue(d, 3);
        const approvalSig = GetValue(d, 4);
        return new AdminAuthorization(adminContext, adminCert, adminAuthMessage, blindSig, approvalSig);
    }
}


function arrayEquals(a, b) {
    if (a.length !== b.length) return false;
    return a.every((val, idx) => val === b[idx]);
}
