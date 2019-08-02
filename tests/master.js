import tide from './test-config'



async function createAccount(username, password) {
    try {
        const result = await tide.createMasterAccount(username, password, false);
        console.log(result);
    } catch (error) {
        console.log(error);
    }
}

const username = `user${Math.floor(Math.random() * (100000000 - 1 + 1)) + 1}`;
const password = `password${Math.floor(Math.random() * (100000000 - 1 + 1)) + 1}`
createAccount(username, password);