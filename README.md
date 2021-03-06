# tide-js

A Javascript library to create and assemble accounts in the Tide ecosystem.

```
npm install tide-js
```

## Initialization
```javascript
import Tide from 'tide-js';
const tide = new Tide(['ork-endpoint-1','ork-endpoint-2'], 256); // Ork nodes, encryption strength
```


## Creating an account
```javascript
const result = await tide.postCredentials('username', 'password');
```


## Assembling an account
```javascript
const account = await tide.getCredentials('username', 'password'));
```


## Encryption & decryption
```javascript
const secretMsg = 'So long, and thanks for all the fish.';
const encrypted = await tide.processEncryption(true, secretMsg, keys.pub); // Encrypt, data, key

const decrypted = await tide.processEncryption(false, encrypted, keys.priv);
```
