import Tide from "../tide";
import config from "./test-config"

const tide = new Tide(config.nodes)

async function login(username, password) {
    try {
        const result = await tide.getCredentials(username, password);

        console.log(`Test completed successfully`);
        console.log(`Keys: `, result);
    } catch (error) {
        console.log(error);
    }
}

const credentials = {
    username: "user97745100",
    password: "password62478579"
}

login(credentials.username, credentials.password);