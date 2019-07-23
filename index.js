/* 
 * Tide Protocol - Infrastructure for the Personal Data economy
 * Copyright (C) 2019 Tide Foundation Ltd
 *	
 * This program is free software and is subject to the terms of
 * the Tide Community Open Source Licence as published by the 
 * Tide Foundation Limited. You may modify it and redistribute 
 * it in accordance with and subject to the terms of that licence.
 * This program is distributed WITHOUT WARRANTY of any kind, 
 * including without any implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  
 * See the Tide Community Open Source Licence for more details.
 * You should have received a copy of the Tide Community Open 
 * Source Licence along with this program.  
 * If not, see https://tide.org/licenses/tcosl-1.0.en.html
 */

import elGamal from './src/cryptide.js'

import ecc from 'eosjs-ecc'
import {
    JsSignatureProvider
} from 'eosjs/dist/eosjs-jssig'; // development only
import {
    Api,
    JsonRpc,
    RpcError
} from 'eosjs';

const signatureProvider = new JsSignatureProvider(["5JMzv4Q5Qtd2xGoPhSNWNFkBH7dLJ3RUr6BQ2We58xWohCEngUa"]);

const rpc = new JsonRpc('http://104.43.250.225:8888');
const api = new Api({
    rpc,
    signatureProvider
});
//uint64_t vendor_username, name account, uint64_t account_username, uint64_t time)
//7365744080294536752,"tidexdroplet", 7089007990059132210, 100
(async () => {
    const result = await api.transact({
        actions: [{
            account: 'xtidemasterx',
            name: 'inituser',
            authorization: [{
                actor: 'xtidemasterx',
                permission: 'active',
            }],
            data: {
                vendor_username: '7365744080294536752',
                account: 'eosjs',
                account_username: 777333,
                time: '999',
            },
        }]
    }, {
        blocksBehind: 3,
        expireSeconds: 30,
    });
    console.log(result);
})();

export default class Tide {
    constructor(orkNodes, vendorEndpoint, vendorUsername, blockchainEndpoint, encryptionStrength = 32) {
        this.nodeArray = orkNodes;
        this.threshold = orkNodes.length - 1;
        this.hashes = [];
        this.encryptionStrength = encryptionStrength;
        this.vendorEndpoint = vendorEndpoint;
        this.vendorUsername = vendorUsername;
        this.blockchainEndpoint = blockchainEndpoint;
    }

    createMasterAccount(username, password, useOrks) {
        var self = this;
        return new Promise(
            async function (resolve, reject) {
                try {
                    const hashedCreds = self.hashUsername(username);

                    // Create keys
                    const keys = await createBlockchainKeys();

                    // Initialize the account
                    const accountResult = await self.tideRequest(`${self.vendorEndpoint}/${actions.INIT_USER}`, {
                        username: hashedCreds.username,
                        publicKey: keys.pub
                    });

                    if (!accountResult.success) return reject(accountResult.error);

                    if (useOrks) {
                        // Create fragments
                        const frags = elGamal.shareText(keys.priv, self.nodeArray.length, self.threshold);

                        // Hash password and get the password fragments
                        self.hashes = await elGamal.hashPasswords(password, hashedCreds.salt, self.nodeArray);

                        // Send fragments to the ork nodes
                        await postFragments(self.nodeArray, keys.pub, frags, hashedCreds.username, self.hashes, null);
                    }

                    // Confirm the account
                    await self.tideRequest(`${self.vendorEndpoint}/${actions.CONFIRM_USER}`, {
                        username: hashedCreds.username
                    });

                    return resolve({
                        pub: keys.pub,
                        priv: keys.priv,
                        account: accountResult.content,
                        username: hashedCreds.username
                    });
                } catch (thrownError) {
                    return reject(thrownError);
                }
            });
    }

    createVendorAccount(username, password, useOrks) {
        var self = this;
        return new Promise(
            async function (resolve, reject) {
                try {
                    const hashedCreds = self.hashUsername(username);

                    // Create keys
                    const keys = self.createKeys();

                    if (useOrks) {
                        // Create elGamal fragments
                        const frags = elGamal.shareKey(keys.priv, self.nodeArray.length, self.threshold);

                        // Hash password and get the password fragments
                        self.hashes = await elGamal.hashPasswords(password, hashedCreds.salt, self.nodeArray);

                        // Send fragments to ork nodes
                        await postFragments(self.nodeArray, keys.pub, frags, hashedCreds.username, self.hashes, self.vendorUsername);
                    }

                    return resolve(keys);
                } catch (thrownError) {
                    return reject(thrownError);
                }
            }
        );
    }

    getCredentials(username, password) {
        var self = this;
        return new window.Promise(
            async function (resolve, reject) {
                const id = nextId();
                log(id, `gathering user nodes...`)
                try {
                    const hashedCreds = self.hashUsername(username);

                    // Gather the nodes the user used to register with Tide
                    const userNodes = await tideRequest(`${self.nodeArray[0]}/nodes`, {
                        username: hashedCreds.username
                    });

                    log(id, `Gathered user nodes. Count: ${userNodes.length}`)
                    log(id, `Creating password fragments`)

                    self.hashes = await elGamal.hashPasswords(password, hashedCreds.salt, userNodes.map(n => n.ork_url));

                    // Get the fragments from each node
                    const fragmentResult = await getFragments(userNodes, hashedCreds.username, password, self.hashes, self.threshold);

                    return resolve(fragmentResult);
                } catch (thrownError) {
                    log(nextId(), thrownError, 'error')
                    return reject();
                }
            }
        );
    }

    encryptUsingMaster(data, myPrivate, targetPublic) {
        return ecc.Aes.encrypt(myPrivate, targetPublic, data);
    }

    decryptUsingMaster(data, myPrivate, targetPublic) {
        return ecc.Aes.decrypt(myPrivate, targetPublic, data.nonce, data.message, data.checksum)
    }

    processEncryption(encrypt, data, key) {
        return new window.Promise(
            async function (resolve, reject) {
                try {
                    if (data == '' || data == null) return resolve('');
                    return resolve(encrypt ? elGamal.encrypt(data, key) : elGamal.decrypt(data, key))
                } catch (error) {
                    return reject("Incorrect private key");
                }
            });
    }

    hashUsername(data) {
        var salt = elGamal.hashSha(data)
        var username = elGamal.hashSha(salt) // Master account username
        var userVendorUsername = elGamal.hashSha(`${salt}-${this.vendorUsername}`) // Vendor specific username
        return {
            salt: salt,
            username: username,
            userVendorUsername: userVendorUsername
        };
    }

    tideRequest(url, data) {
        return executeTideRequest(url, data)
    }

    createKeys() {
        const [privateKey, publicKey] = elGamal.getKeys(self.encryptionStrength);
        return {
            priv: privateKey,
            pub: publicKey
        }
    }
}

function postFragments(nodes, pub, frags, username, hashes, vendor) {
    return new Promise(
        async function (resolve, reject) {
            var complete = 0;

            for (let i = 0; i < nodes.length; i++) {

                const nodeIndex = i;
                const model = {
                    username: username,
                    accountPublic: pub,
                    accountPrivateFrag: frags[i],
                    PasswordHash: hashes.find(h => h.server == nodes[nodeIndex]).pass,
                    vendor: vendor
                };

                await executeTideRequest(nodes[nodeIndex] + "/PushFragment", model).then((r) => {
                    if (r.success) {
                        complete++;
                    } else {
                        return reject(r.error);
                    }

                    if (complete == nodes.length) {
                        return resolve();
                    }
                }).catch((e) => {
                    log(nextId(), `Failed pushing fragments`)
                });
            }
        });
}

function getFragments(nodes, username, password, hashes, threshold) {
    return new window.Promise(
        async function (resolve, reject) {
            var frags = [];
            var failedCount = 0;
            const id = nextId();
            const failId = nextId();

            // Seed transient keys
            log(nextId(), `Generating transient key-pair for transmission encryption`)
            const [priv, pub] = elGamal.getKeys(32);

            log(id, `Gathering fragments. ${frags.length}/${nodes.length}`)
            const model = {
                username: username,
                publicKey: pub,
                passwordHash: ""
            };

            const results = nodes.map((n) => tideRequest(`${n.ork_url}/login`, appendHash(model, n.ork_url, hashes)));

            for (const r of results) {
                await r.then((content) => {
                    frags.push(content);
                    log(id, `Gathering fragments. ${frags.length}/${nodes.length}`)
                    if (frags.length == threshold) {

                        log(id, `Finished gathering fragments`, 'success')

                        return resolve({
                            priv: elGamal.combineKeys(frags.map(f => elGamal.decrypt(f.vendorFragment.private_key_frag, priv))),
                            pub: frags[0].vendorFragment.public_key
                        });
                    }
                }).catch((e) => {
                    log(failId, `Failed gathering ${failedCount++} fragments`)
                    if (failedCount > nodes.length - threshold) return reject(e);
                });
            }
        });
}

function tideRequest(url, data) {
    return new window.Promise(
        async function (resolve, reject) {
            const http = new XMLHttpRequest();
            http.onreadystatechange = function () {
                if (this.readyState === 4) {
                    if (this.status === 200) {
                        const content = JSON.parse(this.responseText);
                        if (content.success) return resolve(content.content);
                        return reject(content.error);
                    } else return reject(this.error);
                }
            };
            http.open(data != null ? "POST" : "GET", url);
            if (data != null) {
                http.setRequestHeader("Content-type", "application/json; charset=utf-8");
                http.send(JSON.stringify(data));
            } else {
                http.send();
            }
        });
}

function appendHash(model, node, hashes) {
    model.passwordHash = hashes.find(h => h.server == node).pass;
    return model;
}

var currentId = 0;

function nextId() {
    return currentId++;
}

function log(id, msg, type = 'log') {
    document.dispatchEvent(new CustomEvent("tide-log", {
        detail: {
            id: id,
            msg: msg,
            type: type,
        }
    }));
}

function executeTideRequest(url, data) {
    return new window.Promise(
        async function (resolve, reject) {
            const http = new XMLHttpRequest();
            http.onreadystatechange = function () {
                if (this.readyState === 4) {
                    if (this.status === 200) {
                        const content = JSON.parse(this.responseText);
                        if (content.success) return resolve(content);
                        return reject(content.error);
                    } else return reject(this.error);
                }
            };
            http.open(data != null ? "POST" : "GET", url);
            if (data != null) {
                http.setRequestHeader("Content-type", "application/json; charset=utf-8");
                http.send(JSON.stringify(data));
            } else {
                http.send();
            }
        });
}

function createBlockchainKeys() {
    return new window.Promise(
        async function (resolve, reject) {
            ecc.randomKey().then(privateKey => {
                return resolve({
                    priv: privateKey,
                    pub: ecc.privateToPublic(privateKey)
                })
            })
        });
}

function getBlockchainClient(privateKey, endpoint) {
    const signatureProvider = new JsSignatureProvider([privateKey]);

    const rpc = new JsonRpc(endpoint);
    return new Api({
        rpc,
        signatureProvider
    });
}

const actions = {
    INIT_USER: 'initializeAccount',
    CONFIRM_USER: 'confirmAccount'
}