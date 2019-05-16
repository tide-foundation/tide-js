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
export default class Tide {
    constructor(orkNodes) {
        this.nodeArray = orkNodes;
        this.threshold = orkNodes.length - 1;
        this.hashes = [];
    }

    postCredentials(username, password) {
        var self = this;
        return new Promise(
            async function (resolve, reject) {
                try {
                    const saltAndUser = self.hashUsername(username);

                    // Create fragments
                    const [cvkPrv, cvkPub] = elGamal.getKeys();
                    const frags = elGamal.shareKey(cvkPrv, self.nodeArray.length, self.threshold);

                    self.hashes = await elGamal.hashPasswords(password, saltAndUser.salt, self.nodeArray);

                    await self.tideRequest(`${self.nodeArray[0]}/CreateAccount?publickey=notused&username=${saltAndUser.username}`)

                    // Send fragments to ork nodes
                    const sendFragmentsResult = await postFragments(self.nodeArray, cvkPub, frags, saltAndUser.username, self.hashes);

                    return resolve({
                        pub: cvkPub,
                        priv: cvkPrv
                    });
                } catch (thrownError) {
                    return reject(`Failed sending fragments to all selected orks with error: ${thrownError}`);
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
                    const saltAndUser = self.hashUsername(username);

                    // Gather the nodes the user used to register with Tide
                    const userNodes = await tideRequest(`${self.nodeArray[0]}/nodes`, {
                        username: saltAndUser.username
                    });

                    log(id, `Gathered user nodes. Count: ${userNodes.length}`)
                    log(id, `Creating password fragments`)
                    console.log(self.nodeArray)
                    console.log(userNodes)
                    self.hashes = await elGamal.hashPasswords(password, saltAndUser.salt, userNodes.map(n => n.ork_url));

                    // Get the fragments from each node
                    const fragmentResult = await getFragments(userNodes, saltAndUser.username, password, self.hashes, self.threshold);

                    return resolve(fragmentResult);
                } catch (thrownError) {
                    log(nextId(), thrownError, 'error')
                    return reject();
                }
            }
        );
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
        var username = elGamal.hashSha(salt)
        return {
            salt: salt,
            username: username
        };
    }

    tideRequest(url, data) {
        return executeTideRequest(url, data)
    }
}

function postFragments(nodes, cvkPublic, frags, username, hashes) {
    return new Promise(
        async function (resolve, reject) {
            var complete = 0;

            for (let i = 0; i < nodes.length; i++) {

                const nodeIndex = i;
                const model = {
                    username: username,
                    cvkPublic: cvkPublic,
                    cvkPrivateFrag: frags[i],
                    PasswordHash: hashes.find(h => h.server == nodes[nodeIndex]).pass
                };

                executeTideRequest(nodes[nodeIndex] + "/PushFragment", model).then((r) => {
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