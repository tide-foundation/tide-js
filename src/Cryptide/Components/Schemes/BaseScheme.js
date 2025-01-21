export default class BaseScheme{
    static Name = () => { throw Error("Name not implemented"); }
    GetVerifyingFunction = () => { throw Error("Verifying function not implemented"); }
    GetSigningFunction = () => { throw Error("Signing function not implemented"); }
    GetEncryptingFunction = () => { throw Error("Encrypting function not implemented"); }
}