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
 *
 */

import cryptide from './cryptide';
import axios from 'axios';

import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'; // development only
import ecc from 'eosjs-ecc';
import { Api, JsonRpc, RpcError } from 'eosjs';

export default class Tide {
  constructor(
    orkNodes,
    vendorEndpoint,
    vendorUsername,
    blockchainEndpoint,
    encryptionStrength = 32,
    loggerInstance = null,
  ) {
    this.nodeArray = orkNodes;
    this.threshold = orkNodes.length - 1;
    this.encryptionStrength = encryptionStrength;
    this.vendorEndpoint = vendorEndpoint;
    tempVendorEndpoint = vendorEndpoint;
    this.vendorUsername = vendorUsername;
    this.blockchainEndpoint = blockchainEndpoint;
    this.authorizedAccount = null;
    this.client = null;
    logger = loggerInstance;
  }

  createMasterAccount(username, password, useOrks) {
    var self = this;
    return new Promise(async function(resolve, reject) {
      try {
        await self.setAccount(username);

        // Select Orks
        logEvent('Gather Ork', `Gathering orks for master account creation...`);
        var selectedOrks = await gatherOrks(self.nodeArray, self.authorizedAccount.username, self.vendorEndpoint);

        // Create keys
        const keys = await createBlockchainKeys();

        // Initialize the account
        logEvent('Initialize', `Initializing the account...`);
        const accountResult = (
          await axios.post(`${self.vendorEndpoint}/${actions.INIT_USER}`, {
            username: self.authorizedAccount.username,
            publicKey: keys.pub,
          })
        ).data;

        if (!accountResult.success) return reject(accountResult.error);

        logEvent('Initialize', `Successfully initialized the account`);
        self.authorizedAccount.account = accountResult.content;
        self.client = getBlockchainClient(keys.priv, self.blockchainEndpoint);

        if (useOrks) {
          logEvent('Fragments', `Creating ${selectedOrks.length} fragments...`);

          // Create fragments
          const frags = cryptide.shareText(keys.priv, selectedOrks.length, self.threshold);

          // Hash password and get the password fragments
          const hashes = await cryptide.hashPasswords(password, self.authorizedAccount.salt, selectedOrks);

          // Send fragments to the ork nodes
          logEvent('Fragments', `Starting to push fragments to the blockchain...`);
          await postFragments(
            selectedOrks,
            self.vendorUsername,
            keys.pub,
            frags,
            hashes,
            self.authorizedAccount.account,
            self.client,
            self.authorizedAccount.username,
          );
          logEvent('Fragments', `All fragments have been commited to the blockchain successfully`);
        }

        // Confirm the account
        logEvent('Confirming', `Confirming the account...`);
        await self.tideRequest(`${self.vendorEndpoint}/${actions.CONFIRM_USER}`, {
          username: self.authorizedAccount.username,
        });
        logEvent('Confirming', `Successfully confirmed the account`);

        return resolve({
          pub: keys.pub,
          priv: keys.priv,
          account: self.authorizedAccount.account,
          username: self.authorizedAccount.username,
        });
      } catch (thrownError) {
        logEvent('Error', thrownError);
        return reject(thrownError);
      }
    });
  }

  createVendorAccount(username, password, useOrks) {
    var self = this;
    return new Promise(async function(resolve, reject) {
      try {
        // Select Orks
        logEvent('Gather Ork', `Gathering orks for vendor account creation...`);
        var selectedOrks = await gatherOrks(self.nodeArray, self.authorizedAccount.username, self.vendorEndpoint);

        // Create keys
        logEvent('Generating', `Generating Tide keys...`);
        const keys = self.createKeys();

        if (useOrks) {
          logEvent('Fragments', `Creating ${selectedOrks.length} fragments...`);

          // Create cryptide fragments
          const frags = cryptide.shareKey(keys.priv, self.nodeArray.length, self.threshold);

          // Hash password and get the password fragments
          const hashes = await cryptide.hashPasswords(password, self.authorizedAccount.salt, self.nodeArray);

          // Send fragments to ork nodes
          logEvent('Fragments', `Starting to push fragments to the blockchain...`);
          await postFragments(
            selectedOrks,
            await tempConvertUsername(self.vendorUsername),
            keys.pub,
            frags,
            hashes,
            self.authorizedAccount.account,
            self.client,
            self.authorizedAccount.username,
          );

          logEvent('Fragments', `All fragments have been commited to the blockchain successfully`);
        }

        await self.tideRequest(`${self.vendorEndpoint}/${actions.ADD_USER}`, {
          username: self.authorizedAccount.username,
        });

        return resolve(keys);
      } catch (thrownError) {
        logEvent('Error', thrownError);
        return reject(thrownError);
      }
    });
  }

  getCredentials(username, password) {
    var self = this;
    return new window.Promise(async function(resolve, reject) {
      try {
        await self.setAccount(username);

        logEvent('Gather Ork', `Gathering ork nodes used for account creation...`);
        const userNodes = await gatherUserOrks(self.blockchainEndpoint, self.authorizedAccount.username);

        logEvent('Fragments', `Creating password fragments...`);
        const hashes = await cryptide.hashPasswords(
          password,
          self.authorizedAccount.salt,
          userNodes.map(n => n.url),
        );

        logEvent('Fragments', `Fetching fragments from ork nodes...`);
        const fragmentResult = await getFragments(
          userNodes,
          self.authorizedAccount.username,
          password,
          hashes,
          self.threshold,
        );

        return resolve(fragmentResult);
      } catch (thrownError) {
        logEvent('Error', thrownError);
        return reject(thrownError);
      }
    });
  }

  masterEncrypt(data, myPrivate, targetPublic) {
    return ecc.Aes.encrypt(myPrivate, targetPublic, data);
  }

  masterDecrypt(data, myPrivate, targetPublic) {
    return ecc.Aes.decrypt(myPrivate, targetPublic, data.nonce, data.message, data.checksum);
  }

  processEncryption(encrypt, data, key) {
    return new window.Promise(async function(resolve, reject) {
      try {
        if (data == '' || data == null) return resolve('');
        return resolve(encrypt ? cryptide.encrypt(data, key) : cryptide.decrypt(data, key));
      } catch (error) {
        return reject('Incorrect private key');
      }
    });
  }

  async hashUsername(data) {
    var salt = cryptide.hashSha(data);
    var username = cryptide.hashSha(salt); // Master account username
    var userVendorUsername = cryptide.hashSha(`${salt}-${this.vendorUsername}`); // Vendor specific username

    var intUsername = await tempConvertUsername(username);
    var intVendorUsername = await tempConvertUsername(userVendorUsername);
    return {
      salt: salt,
      username: intUsername,
      userVendorUsername: intVendorUsername,
    };
  }

  async setAccount(username) {
    this.authorizedAccount = await this.hashUsername(username);
  }

  tideRequest(url, data) {
    return executeTideRequest(url, data);
  }

  createKeys() {
    const [privateKey, publicKey] = cryptide.getKeys(self.encryptionStrength);
    return {
      priv: privateKey,
      pub: publicKey,
    };
  }
}

var logger = null;
var tempVendorEndpoint = null;

function logEvent(type, msg) {
  if (logger == null) return;
  logger({
    type: type,
    msg: msg,
  });
}

async function tempConvertUsername(username) {
  return (
    await axios.post(`${tempVendorEndpoint}/TempConvertUsername`, {
      content: username,
    })
  ).data.toString();
}

// Compiled a list of orks available for account creation
async function gatherOrks(orkUrls, username, vendorEndpoint) {
  var assembledOrks = [];
  for (let i = 0; i < orkUrls.length; i++) {
    var username = (await axios.get(`${orkUrls[i]}/api/Authentication/Username`)).data.username;
    var usernameForOrk = await tempConvertUsername(cryptide.hashSha(`${username}${username}`));

    assembledOrks.push({
      url: orkUrls[i],
      username: username,
      usernameForOrk: usernameForOrk,
    });
    logEvent('Gather Ork', `Gathered ork node with username: ${username}`);
  }
  return assembledOrks;
}

// Gathers the user-specific orks used during creation
async function gatherUserOrks(endpoint, username) {
  const userNodes = await getTableRow(endpoint, 'xtidemasterx', 'xtidemasterx', 'tideusers', username);

  for (let i = 0; i < userNodes.length; i++) {
    var rows = await getTableRow(endpoint, 'xtidemasterx', 'xtidemasterx', 'orks', userNodes[i].id);
    userNodes[i].url = rows[0].url;
  }

  return userNodes;
}

function postFragments(
  nodes,
  vendorUsername,
  pubToDisplay,
  privFragsToShare,
  passwordHashes,
  auth,
  client,
  tempUsernameInsteadOfOrkSpecificOne,
) {
  return new Promise(async function(resolve, reject) {
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
        logEvent('Fragments', `${i + 1}/${nodes.length}`);
      }
      return resolve();
    } catch (error) {
      return reject();
    }
  });
}

function getFragments(nodes, username, password, hashes, threshold) {
  return new window.Promise(async function(resolve, reject) {
    var frags = [];
    var failedCount = 0;

    // Seed transient keys
    logEvent('Fragments', `Generating transient key-pair for transmission encryption`);
    const [priv, pub] = cryptide.getKeys(32);

    logEvent('Fragments', `Gathering fragments. ${frags.length}/${nodes.length}`);
    const model = {
      username: username,
      publicKey: pub,
      passwordHash: '',
    };

    const results = nodes.map(n => axios.post(`${n.url}/getFragment`, appendHash(model, n.url, hashes)));

    for (const r of results) {
      await r
        .then(content => {
          frags.push(content);
          logEvent('Fragments', `Gathering fragments. ${frags.length}/${nodes.length}`);
          if (frags.length == threshold) {
            logEvent('Fragments', `Finished gathering fragments`);

            return resolve({
              priv: cryptide.combineKeys(frags.map(f => cryptide.decrypt(f.vendorFragment.private_key_frag, priv))),
              pub: frags[0].vendorFragment.public_key,
            });
          }
        })
        .catch(e => {
          logEvent('Fragments', `Failed gathering ${failedCount++} fragments`);
          if (failedCount > nodes.length - threshold) return reject(e);
        });
    }
  });
}

function appendHash(model, node, hashes) {
  model.passwordHash = hashes.find(h => h.server == node).pass;
  return model;
}

function executeTideRequest(url, data, parse = false) {
  return new window.Promise(async function(resolve, reject) {
    const http = new XMLHttpRequest();
    http.onreadystatechange = function() {
      if (this.readyState === 4) {
        if (this.status === 200) {
          return resolve(parse ? JSON.parse(this.responseText) : this.responseText);
        } else return reject(this.error);
      }
    };
    http.open(data != null ? 'POST' : 'GET', url);
    if (data != null) {
      http.setRequestHeader('Content-type', 'application/json; charset=utf-8');
      http.send(JSON.stringify(data));
    } else {
      http.send();
    }
  });
}

function createBlockchainKeys() {
  return new window.Promise(async function(resolve, reject) {
    ecc.randomKey().then(privateKey => {
      return resolve({
        priv: privateKey,
        pub: ecc.privateToPublic(privateKey),
      });
    });
  });
}

function getBlockchainClient(privateKey, endpoint) {
  const signatureProvider = new JsSignatureProvider([privateKey]);

  const rpc = new JsonRpc(endpoint);
  return new Api({
    rpc,
    signatureProvider,
  });
}

async function getTableRow(endpoint, contract, scope, table, lowerBound = 0, limit = 1) {
  return (
    await new JsonRpc(endpoint).get_table_rows({
      code: contract,
      scope: scope,
      table: table,
      json: true,
      lower_bound: lowerBound,
      limit: limit,
    })
  ).rows;
}

async function transaction(client, contract, scope, auth, data) {
  return new window.Promise(async function(resolve, reject) {
    try {
      await client.transact(
        {
          actions: [
            {
              account: contract,
              name: scope,
              authorization: [
                {
                  actor: auth,
                  permission: 'active',
                },
              ],
              data: data,
            },
          ],
        },
        blockchainSettings,
      );
      return resolve();
    } catch (error) {
      return reject(error);
    }
  });
}

const actions = {
  INIT_USER: 'initializeAccount',
  CONFIRM_USER: 'confirmAccount',
  POST_FRAGMENT: 'postfragment',
  ADD_USER: 'adduser',
};

const blockchainSettings = {
  blocksBehind: 3,
  expireSeconds: 30,
};

window.Tide = Tide;

// var tidedd = new Tide([
//     'https://droplet-ork-1.azurewebsites.net',
//     'https://droplet-ork-2.azurewebsites.net',
//     'https://droplet-ork-3.azurewebsites.net'
// ], `https://localhost:5001/api/tide`, "5145206732613769841", 'http://104.43.250.225:8888', 32, (log) => console.log());

// async function lol() {
//     try {

//         var randomName = `email${Math.floor(Math.random() * (+10000 - +1)) + +1}s@gmail.com`;

//         var masterResult = await tidedd.createMasterAccount(randomName, 'password', true);
//         console.log(masterResult)
//         var vendorResult = await tidedd.createVendorAccount(randomName, 'password', true);
//         console.log(vendorResult)
//         // var result = await tidedd.getCredentials('thraksdfd222sffffmar@gmail.com', 'password');
//         // console.log(result);

//         //  console.log(result)
//     } catch (error) {
//         console.log(error)
//     }
// }

// lol();
