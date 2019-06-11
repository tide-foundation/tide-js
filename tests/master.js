import Tide from "../tide";
import config from "./test-config"

const tide = new Tide([], '', 'tide');



async function createAccount(username, password) {
    try {
        const registerVendorResult = await tide.createMasterAccount(username, password, false);
        console.log(registerVendorResult)
        console.log(`Test completed successfully`);
        console.log(`Credentials: `, {
            "username": username,
            "password": password
        });
        console.log(`Keys: `, registerVendorResult);
    } catch (error) {
        console.log(error);
    }
}

const username = `user${Math.floor(Math.random() * (100000000 - 1 + 1)) + 1}`;
const password = `password${Math.floor(Math.random() * (100000000 - 1 + 1)) + 1}`
createAccount(username, password);