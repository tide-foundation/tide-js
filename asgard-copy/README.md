# Asgard
Vendor server-side libraries to validate and test Tide Security. 

## Quick overview of Tide specific terminologies
### Tide Request
The data object used to communicate with the Tide Network. All information regarding the context of what you want to execute is provided inside this object.
Fields of is object include request name, id, authorization flow requested, authorized data, informational data etc.
### Policies and Contracts
Together, policies and contracts create a rule system designed by you, enforced by the Tide Network. 
Think of a contract as the function used to validate a request, and a policy as the parameters to that function.

Pseudocode example of policies + contracts:
```js
// You create the policy
your_policy = {
    max_btc_to_send: 5,
    time_of_day_allowed: "between 10am and 4pm"
}

// You upload your own contract, or use one provided by the Network
function your_contract_validate_func(policy){
    check current time is in policy.time_of_day_allowed
    check tx to sign is sending less than policy.max_btc_to_send
    return success
}

// The network enforces your policy
if your_contract_validate_func(your_policy) is success {
    execute request
}
```

## Policies
A policy is a data object that contains a set of parameters which validate a specific tide request against a contract.

### Policy Structure
A policy consists of a couple fields:
- `contractId` : The contract id that your policy is meant to execute against.
- `modelId` : The model id (request type) your policy/contract will validate the contents of. Could be Cardano Transaction, code signing, token signature etc.
- `keyId` : Your vendor id
- `approvalType`: Either set to `explicit` or `implicit`. Set to `explicit` if you require the user(s) to manually approve the use of the policy with a request, or set to `implicit` if you don't require the user to manually approve its use, thus allowing its use without the user of the policy knowing.
- `executionType`: Either set to `public` or `private`. Set ot `public` if you'd like anyone to be able to execute and retrieve the contents of the request. Or set to `private` if specific conditions for the user executing the request must be met (**logic set in contract**).
- `params` : A key/value map of the specific values your contract requires to validate the contents of the request. This is what gets enforced by your contract onto the request.
- `signature` : The signature of the policy from your vendor key. This is required to use a policy on the Tide Network.

Creating a policy:
```js
const policyParameters = new Map();
policyParameters.set("myNumberParam", 1);
policyParameters.set("myStringParam", "test");
policyParameters.set("myBigIntParam", BigInt(2));
policyParameters.set("myBooleanParam", true);
policyParameters.set("myByteArrayParam", new Uint8Array([0, 2, 1, 3]));

const policy = new Policy({
    modelId: "<model id to use with this policy>",
    contractId: "<contract id to use with this policy>",
    keyId: "<your vendor id>",
    approvalType: "explicit",
    executionType: "public",
    params: policyParameters
});
```

### Creating a policy for your organization
Any policy you create will create a linkage between either a single Tide Request and a single Contract - or any Tide Request and a single Contract. 

The relationship betweent the contract, policy and tide request is as follows:
1. Contract contains the logic to check policy parameters against a tide request. Contract logic sits on the network's nodes.
2. The policy contains the actual values the contract will check the tide request against. Policies sit on specific applications using the policy (such as a crypto wallet).
3. The tide request contains the policy as part of its payload when sent to the network. Aside from that it is simply a data model.

To create a policy, you'll have to create the Policy object then execute a PolicySignRequest to authorize its use. 

Here's the syntax for it:
```js
const policySignRequest = PolicySignRequest.New(policy); // PolicySignRequest will return a single signature of the Policy you added to the PolicySignRequest
const policySignature = // see 7. Executing Tide Requests on tidecloak-js on how to execute a tide request
policy.signature = policySignature;
const policyDataToStore = policy.encode(); // You can now store this signed policy for your client application to use when authorizing tide requests you specified in policy.modelId
```

## Contracts
### Contract Structure
All contracts that execute on the Tide Network require the implementation of 3 functions.

1. `validate_request` - Always required for checking policy details against the request's contents.
2. `validate_approvers` - Required if you intend to use policies with `approvalType` set to **explicit**. This is where the logic that determines if the users that approved this request has the specific roles/conditions to do so.
3. `validate_executor` - Required if you intend to use policies with `executionType` set to **private**. This is where the logic that determines if the user that executed this request had the correct roles/condition to do so.

Constructing a contract on Tide for now is extraodinarily complex and you probably won't be doing it. TODO

## Other specific niches to know about
### Custom Requests
Looking to sign your own kind of custom data with Tide? Look no further. This is where I intend to butcher the explanation of it.

There are 3 types of `CustomRequest` on Tide - each intended to best fit your specific type of request.

1. `BasicCustomRequest` - A basic request. You have all the data your require to be validated at the time of request creation.
2. `DyanmicPayloadCustomRequest` - A request with the data to be signed in the dynamic part of the request (which can be changed from the time the request was created). 
3. `DynamicPayloadApprovedCustomRequest` - A request with the data to be signed in the dynamic part of the request that also requires `explicit` approval from the users. This requires the use of a Human Readable object in the authorized payload to ensure the details shown to an approver at approval time can be verified against the signing data added to the request dynamically later.

### Basic Contract Test Validation