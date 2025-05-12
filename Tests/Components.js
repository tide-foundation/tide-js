import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { Point } from "../Cryptide/Ed25519.js";

export async function Ed25519PublicDeserialization(){
    const gComp = new Ed25519PublicComponent(Point.BASE);
    const serial = gComp.Serialize().ToString();
    console.log(serial);

    const newG = Ed25519PublicComponent.DeserializeComponent(serial);
    console.log(newG)

    const one = new Ed25519PrivateComponent(BigInt(1));
    const oserial = one.Serialize().ToString()
    console.log(oserial);

    const none = Ed25519PrivateComponent.DeserializeComponent(oserial);
    console.log(none);
}