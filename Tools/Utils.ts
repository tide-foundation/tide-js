// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import OrkInfo from "../Models/Infos/OrkInfo";

declare global {
    interface Window {
        tide_env?: string;
    }
}

export const Threshold = (typeof window !== 'undefined' && (window as any).tide_env) === 'staging' ? 3 : 14;
export const Max = (typeof window !== 'undefined' && (window as any).tide_env) === 'staging' ? 5 : 20;

export function CurrentTime(){
	return Math.floor(Date.now() / 1000); // this will be affected by the 2038 problem
}

/**
 * This probably won't work at first
 * @param {Promise[]} promises 
 * @param {string} keyType 
 * @param {number} amountRequired
 * @param {number} customTimeout
 * @param {function} customPromiseChecker
 * @returns 
 */
async function PromiseRace(promises, keyType, amountRequired, customTimeout=null, customPromiseChecker=null) { 
    let results = [];
    let failed = [];
    let timeoutReached = false;
    let initLength = promises.length;

    // Function to set a timeout promise
    const timeout = (ms, id) => new Promise(resolve => setTimeout(resolve, ms, id));

    // Start the timeout checks
    const oneSecondCheck = timeout(1000, '1s');
    const timeoutLength = customTimeout == null ? 8000 : customTimeout;
    const timeoutCheck = timeout(timeoutLength, 'ts');

    promises.push(oneSecondCheck);
    promises.push(timeoutCheck);

    let oneSecCheckPassed = false;
    let fullyCompletedPromises = 0;

    while (promises.length > 0 && fullyCompletedPromises < initLength) {
        const racePromises = promises.map((p, index) => p.then(result => ({result, index})).catch(error => ({error, index})));
        const fastestPromise = await Promise.race(racePromises);

        if (fastestPromise.result === '1s') {
            oneSecCheckPassed = true;
        }else if(fastestPromise.result === 'ts'){
            if (fullyCompletedPromises >= amountRequired) {
                break;
            } 
            else if(failed.length > 0){
                console.log("Errors in flow:")
                failed.forEach(f => console.error(f));
                break;
            }else{
                timeoutReached = true;
                break;
            }
        }else {
            if (!fastestPromise.error) {
                if(customPromiseChecker != null){
                    if(customPromiseChecker(fastestPromise.result)){
                        fullyCompletedPromises++;
                    }
                    results.push(fastestPromise.result); // Promise resolved successfully
                }else{
                    fullyCompletedPromises++;
                    results.push(fastestPromise.result); // Promise resolved successfully
                }
            } else {
                failed.push(fastestPromise.error); // Promise rejected
            }
        }

        // Removed one sec check passed condition for slighly faster requests - add back in when we start penalising orks
        //if(oneSecCheckPassed && fullyCompletedPromises >=amountRequired) break;
        if(fullyCompletedPromises >=amountRequired) break;

        // Remove the resolved or rejected promise from the list
        promises.splice(fastestPromise.index, 1);
    }

    // Error checking and finalization
    if (fullyCompletedPromises >= amountRequired) {
        return results; // Return results if threshold amount is met
    } else {
        if (failed.some(ex => ex === "Too many attempts")) {
            throw Error("enclave.throttled");
        } else if(failed.length > 0){
            throw Error(failed[0]);
        }else if (timeoutReached) {
            throw Error("enclave.thresholdTimeoutFailure");
        } else {
            throw Error(keyType + " Orks for this account are down");
        }
    }
}


/**
 * 
 * @param {OrkInfo[]} orkList_Ref List of ORK infos
 * @param {Promise[]} pre_responses Unresolved Promises
 * @param {string} keyType CMK, CVK?
 * @param {number} number Amount of ORKs to wait for
 * @param {number} amountRequired
 * @param {(0 | 1)[]} bitwise_p
 * @param {*[]} optionalArray
 * @param {number} customTimeout
 * @param {function} customPromiseChecker
 * @returns 
 */
export async function WaitForNumberofORKs(orkList_Ref, pre_responses, keyType, amountRequired=Threshold, bitwise_p=null, optionalArray=null, customTimeout=null, customPromiseChecker=null){
    // See Utils.cs on Midgard Core for how this can be improved
    // Basically, you don't need indexes in the responses, just use .indexOf

    const unsortedResponses = await PromiseRace(pre_responses, keyType, amountRequired, customTimeout, customPromiseChecker);
	const sortedResponses = unsortedResponses.sort((a, b) => a.index - b.index);

    let bitwise = [];
    if(bitwise_p != null){
        // bitwise provided, this func is being called from a sequential flow
        // ork array will be modified 
        // bitwise returned will be new/updated bitwise

        // Get an array of active ork indexs (used to update bitwise)
        let previousActiveOrkIndexes = [];
        bitwise_p.forEach((b, i) => {
            if(b == 1) previousActiveOrkIndexes.push(i);
        });

        // This is too confusing to try and explain. Ask chatgpt.
        // Hint: We have to skip existing unavilable orks in the bitwise and 
        // take the indexes in the unresponsive list as the nth active bitwise element to switch off
        let currentUnresponsiveOrkIndexs = []; // unresponsive ork indexes from an array that previpusly contained only active orks
        let i = 0, j = 0;
        console.log("total: " + orkList_Ref.length);
        console.log("responded: " + sortedResponses.length);
        while (i < orkList_Ref.length && j < sortedResponses.length) {
            if (i === sortedResponses[j].index) {
                i++;
                j++;
            } else {
                currentUnresponsiveOrkIndexs.push(i);
                console.log(orkList_Ref[i].orkID + ":" + orkList_Ref[i].orkURL + " is slow");
                i++;
            }
        }
    
        // Add any remaining elements from orkLiftRef
        while (i < orkList_Ref.length) {
            currentUnresponsiveOrkIndexs.push(i);
            console.log(orkList_Ref[i].orkID + ":" + orkList_Ref[i].orkURL + " is slow");
            i++;
        }
        console.log("didn't respond: " + currentUnresponsiveOrkIndexs.length)
    // TODO: once this works, shorten the code
        bitwise = bitwise_p.slice();

        let occurrenceCount = 0;
        let indexCount = 0;
        for (let i = 0; i < bitwise.length; i++) {
            if (bitwise[i] === 1) {
                occurrenceCount++;
                if (occurrenceCount === currentUnresponsiveOrkIndexs[indexCount] + 1) { // + 1 as we are converting a index to a counter
                    bitwise[i] = 0;
                    indexCount++;
                }
            }
        }

    }else{
        bitwise = Array(Max).fill(0).map((_, i) => sortedResponses.every(resp => resp.index != i) ? 0 : 1);
    }

	const newOrkList = orkList_Ref.filter((_, i) => !sortedResponses.every(resp => resp.index != i)); // if ork at index 0 does not include a response with index 0, remove ork
	orkList_Ref.splice(0, orkList_Ref.length);
	newOrkList.forEach(el => orkList_Ref.push(el));

	if(optionalArray != null){
		const newOptArray = optionalArray.filter((_, i) => !sortedResponses.every(resp => resp.index != i)); // modifies array!
		optionalArray.splice(0, optionalArray.length);
		newOptArray.forEach(el => optionalArray.push(el));
	} 
	// remove index field from json, return the OTHER (unknown to us) field
	const cleanedResponses = sortedResponses.map(resp => {
		for(let key in resp){
			if(resp.hasOwnProperty(key) && key !== "index" && key !== "tag") return resp[key];
		}
		throw Error("WaitForThresholdNumberofORKs should only be used on NodeClient responses that return an index in the JSON");
	});
	return {fulfilledResponses: cleanedResponses, bitwise};
}
/**
 * 
 * @param {any[]} array 
 * @param {number} targetArraySize 
 * @returns {any[]}
 */
export function removeRandomElements(array, targetArraySize) {
    let newArray = array.slice();
    // Check if the array size is > n
    if (newArray.length < targetArraySize) {
        throw new Error("Array size must be greater than n.");
    }
    else if(newArray.length == targetArraySize) return newArray;

    // Randomly remove elements until the array size is n
    while (newArray.length > targetArraySize) {
        let randomIndex = Math.floor(Math.random() * newArray.length);
        newArray.splice(randomIndex, 1);
    }

    return newArray;
}

export function randBetween(x, y) {
    // Swapping x and y if x is greater than y
    x = BigInt(x);
    y = BigInt(y);
    if (x > y) {
        const temp = x;
        x = y;
        y = temp;
    }
    // Generating random BigInt between x and y
    const range = BigInt(y) - BigInt(x) + BigInt(1);
    const randNum = Math.floor(Math.random() * Number(range));
    const rand = BigInt(randNum);
    return rand + BigInt(x);
}

  /**
   * @param {OrkInfo[]} orks 
   */
export function sortORKs(orks){ 
    const orkRef = orks.slice(); // don't modify original
    return orkRef.sort((a, b) => {
        if(BigInt(a.orkID) < BigInt(b.orkID)) return -1;
        if(BigInt(a.orkID) > BigInt(b.orkID)) return 1;
        return 0
    })
}


export function randomiseEmails(arr) {
    // Thanks ChatGPT
    // Validation
    if (arr == null) {
        return Array(Max).fill(null);
    }

    // Prepare the output array
    let output = [];
    const repetitions = Math.floor(Max / arr.length); // Base number of repetitions for each element
    let remainingSpaces = Max % arr.length; // Additional repetitions needed

    // Fill the output array
    arr.forEach(item => {
        for (let i = 0; i < repetitions; i++) {
            output.push(item);
        }
        if (remainingSpaces > 0) {
            output.push(item);
            remainingSpaces--;
        }
    });

    // Shuffle the output array (Fisher-Yates shuffle)
    for (let i = output.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [output[i], output[j]] = [output[j], output[i]]; // Swap elements
    }

    return output;
}
