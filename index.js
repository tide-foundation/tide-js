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

import cryptide from './src/cryptide'
import axios from 'axios'

import {
    JsSignatureProvider
} from 'eosjs/dist/eosjs-jssig'; // development only
import ecc from 'eosjs-ecc'
import {
    Api,
    JsonRpc,
    RpcError
} from 'eosjs';


export default class Tide {
    constructor(orkNodes, vendorEndpoint, vendorUsername, blockchainEndpoint, encryptionStrength = 32) {
        this.nodeArray = orkNodes;
        this.threshold = orkNodes.length - 1;
        this.encryptionStrength = encryptionStrength;
        this.vendorEndpoint = vendorEndpoint;
        this.vendorUsername = vendorUsername;
        this.blockchainEndpoint = blockchainEndpoint;
        this.authorizedAccount = null;
        this.client = null;
    }

    createMasterAccount(username, password, useOrks) {
        var self = this;
        return new Promise(
            async function (resolve, reject) {
                try {
                    self.authorizedAccount = await self.hashUsername(username);

                    // Select Orks
                    var selectedOrks = await gatherOrks(self.nodeArray, self.authorizedAccount.username, self.vendorEndpoint);

                    // Create keys
                    const keys = await createBlockchainKeys();

                    // Initialize the account
                    const accountResult = (await axios.post(`${self.vendorEndpoint}/${actions.INIT_USER}`, {
                        username: self.authorizedAccount.username,
                        publicKey: keys.pub
                    })).data;

                    if (!accountResult.success) return reject(accountResult.error);

                    self.authorizedAccount.account = accountResult.content;
                    self.client = getBlockchainClient(keys.priv, self.blockchainEndpoint);

                    if (useOrks) {
                        // Create fragments
                        const frags = cryptide.shareText(keys.priv, selectedOrks.length, self.threshold);

                        // Hash password and get the password fragments
                        const hashes = await cryptide.hashPasswords(password, self.authorizedAccount.salt, selectedOrks);

                        // Send fragments to the ork nodes
                        await postFragments(selectedOrks, self.vendorUsername, keys.pub, frags, hashes, self.authorizedAccount.account, self.client, self.authorizedAccount.username);
                    }

                    // Confirm the account
                    await self.tideRequest(`${self.vendorEndpoint}/${actions.CONFIRM_USER}`, {
                        username: self.authorizedAccount.username
                    });

                    return resolve({
                        pub: keys.pub,
                        priv: keys.priv,
                        account: self.authorizedAccount.account,
                        username: self.authorizedAccount.username
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
                    if (self.authorizedAccount == null) await self.hashUsername(username);

                    // Select Orks
                    var selectedOrks = await gatherOrks(self.nodeArray, self.authorizedAccount.username, self.vendorEndpoint);

                    // Create keys
                    const keys = self.createKeys();

                    if (useOrks) {
                        // Create cryptide fragments
                        const frags = cryptide.shareKey(keys.priv, self.nodeArray.length, self.threshold);

                        // Hash password and get the password fragments
                        const hashes = await cryptide.hashPasswords(password, self.authorizedAccount.salt, self.nodeArray);


                        console.log(self.authorizedAccount)
                        // Send fragments to ork nodes
                        await postFragments(selectedOrks, self.vendorUsername, keys.pub, frags, hashes, self.authorizedAccount.account, self.client, self.authorizedAccount.username);
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

                    const hashes = await cryptide.hashPasswords(password, hashedCreds.salt, userNodes.map(n => n.ork_url));

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

    masterEncrypt(data, myPrivate, targetPublic) {
        return ecc.Aes.encrypt(myPrivate, targetPublic, data);
    }

    masterDecrypt(data, myPrivate, targetPublic) {
        return ecc.Aes.decrypt(myPrivate, targetPublic, data.nonce, data.message, data.checksum)
    }

    processEncryption(encrypt, data, key) {
        return new window.Promise(
            async function (resolve, reject) {
                try {
                    if (data == '' || data == null) return resolve('');
                    return resolve(encrypt ? cryptide.encrypt(data, key) : cryptide.decrypt(data, key))
                } catch (error) {
                    return reject("Incorrect private key");
                }
            });
    }

    async hashUsername(data) {
        var salt = cryptide.hashSha(data)
        var username = cryptide.hashSha(salt) // Master account username
        var userVendorUsername = cryptide.hashSha(`${salt}-${this.vendorUsername}`) // Vendor specific username

        var intUsername = await tempConvertUsername(username);
        var intVendorUsername = await tempConvertUsername(userVendorUsername);
        return {
            salt: salt,
            username: intUsername,
            userVendorUsername: intVendorUsername
        };
    }

    tideRequest(url, data) {
        return executeTideRequest(url, data)
    }

    createKeys() {
        const [privateKey, publicKey] = cryptide.getKeys(self.encryptionStrength);
        return {
            priv: privateKey,
            pub: publicKey
        }
    }
}

async function tempConvertUsername(username) {
    return (await axios.get(`https://localhost:5001/api/tide/TempConvertUsername/${encodeURIComponent(username)}`)).data.toString();
}

async function gatherOrks(orkUrls, username, vendorEndpoint) {
    var assembledOrks = [];
    for (let i = 0; i < orkUrls.length; i++) {
        var username = (await axios.get(`${orkUrls[i]}/api/Authentication/Username`)).data.username;
        var usernameForOrk = await tempConvertUsername(cryptide.hashSha(`${username}${username}`));

        assembledOrks.push({
            url: orkUrls[i],
            username: username,
            usernameForOrk: usernameForOrk
        })
    }
    return assembledOrks;
}

function postFragments(nodes, vendorUsername, pubToDisplay, privFragsToShare, passwordHashes, auth, client, tempUsernameInsteadOfOrkSpecificOne) {
    return new Promise(
        async function (resolve, reject) {
            try {
                for (let i = 0; i < nodes.length; i++) {
                    await transaction(client, 'xtidemasterx', actions.POST_FRAGMENT, auth, {
                        ork_username: nodes[i].username,
                        username: tempUsernameInsteadOfOrkSpecificOne, //nodes[i].usernameForOrk,
                        vendor: vendorUsername,
                        private_key_frag: privFragsToShare[i],
                        public_key: pubToDisplay,
                        pass_hash: passwordHashes[i],
                    });
                }
                return resolve();
            } catch (error) {
                return reject();
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
            const [priv, pub] = cryptide.getKeys(32);

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
                            priv: cryptide.combineKeys(frags.map(f => cryptide.decrypt(f.vendorFragment.private_key_frag, priv))),
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

function executeTideRequest(url, data, parse = false) {
    return new window.Promise(
        async function (resolve, reject) {
            const http = new XMLHttpRequest();
            http.onreadystatechange = function () {
                if (this.readyState === 4) {
                    if (this.status === 200) {
                        return resolve(parse ? JSON.parse(this.responseText) : this.responseText);
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

async function transaction(client, contract, scope, auth, data) {
    console.log(contract, scope, auth, data)
    return new window.Promise(
        async function (resolve, reject) {
            try {
                await client.transact({
                    actions: [{
                        account: contract,
                        name: scope,
                        authorization: [{
                            actor: auth,
                            permission: 'active',
                        }],
                        data: data,
                    }]
                }, blockchainSettings);
                return resolve();
            } catch (error) {
                console.log(error)
                return reject(error);
            }

        });
}

const actions = {
    INIT_USER: 'initializeAccount',
    CONFIRM_USER: 'confirmAccount',
    POST_FRAGMENT: 'postfragment'
}

const blockchainSettings = {
    blocksBehind: 3,
    expireSeconds: 30,
};