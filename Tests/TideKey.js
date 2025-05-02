import Ed25519Scheme from "../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";
import TideKey from "../Cryptide/TideKey.js";

export default async function Tide_Key(){
    const k = TideKey.NewKey(Ed25519Scheme);
    const msg = new TextEncoder().encode("hello");
    const sig = await k.sign(msg);

    const v = TideKey.FromSerializedComponent(k.get_public_component().Serialize().ToBytes());
    await v.verify(msg, sig);
    console.log("all g")
}