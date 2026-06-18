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
import { TideError, TideErrorDetail } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";

export const Threshold = 3;
export const Max = 5;

/**
 * Reduce an arbitrary thrown value to a {@link TideErrorDetail} entry so the
 * aggregate threshold-failure error can surface per-ORK context (URL, code,
 * displayMessage) without forcing callers to introspect untyped exceptions.
 */
function _toDetail(err: unknown): TideErrorDetail {
    if (TideError.isTideError(err)) {
        return {
            url: err.url,
            endpoint: err.endpoint,
            method: err.method,
            code: err.code,
            displayMessage: err.displayMessage,
            cause: err,
        };
    }
    if (err instanceof Error) {
        return { displayMessage: err.message, cause: err };
    }
    return { displayMessage: String(err), cause: err };
}

export function CurrentTime(){
    const timeSkew = window.localStorage?.getItem("timeSkew");
    const now = Math.floor(Date.now() / 1000);
    return timeSkew ? now + Number(timeSkew) : now;
}

/**
 * Options bag for {@link WaitForNumberofORKs} / {@link PromiseRace}.
 * Added as a bag (not a positional) because the positional list is already 8 long.
 */
export interface WaitForORKsOptions {
    /**
     * Opt-in: when the threshold is NOT met and the failure set covers the
     * ENTIRE attempted cohort (every attempted ORK rejected — no successes,
     * no still-pending promises cut off by the timeout) and EVERY per-ORK
     * failure is a {@link TideError} carrying one identical upstream `code`
     * (and that code is not a tide-js transport code, i.e. does not start
     * with `TIDE-TIDEJS-`), throw a "promoted" TideError carrying that code /
     * messageKey / messageParams instead of the generic
     * `NET_THRESHOLD_FAILURE` aggregate.
     *
     * The full-cohort requirement is a security gate: without it, one fast
     * malicious ORK plus slow/unreachable honest ORKs could fake "unanimity"
     * at the timeout and misrepresent an outage as a cohort-attested error.
     *
     * Used by the reservation flow so a unanimous 409
     * `TIDE-ORK-KEYGEN-USERNAME_RESERVED` survives to the UI. Default: off —
     * all other callers keep byte-identical behaviour.
     */
    promoteUnanimousCodes?: boolean;
}

/**
 * Representative-selection helper for unanimous-code promotion: among the
 * failures whose `messageParams[param]` coerces to a FINITE number, return
 * the failure holding the median value (even count -> lower median), or
 * `null` if no failure qualifies.
 *
 * Median (not max/min) is the honest-majority rule: with one attacker in an
 * otherwise-honest cohort the median is always a value an honest ORK sent,
 * so a single member cannot drag the displayed value to an extreme.
 * Non-finite coercions (NaN, +/-Infinity — e.g. `"9e999"`) are never
 * candidates, so a poisoned value can never win.
 */
function _medianFailureByParam(failures: TideError[], param: string): TideError | null {
    const candidates: { f: TideError; v: number }[] = [];
    for (const f of failures) {
        const raw = (f.messageParams as Record<string, unknown> | null | undefined)?.[param];
        if (raw === undefined || raw === null) continue;
        const v = Number(raw);
        if (!Number.isFinite(v)) continue;
        candidates.push({ f, v });
    }
    if (candidates.length === 0) return null;
    candidates.sort((a, b) => a.v - b.v);
    return candidates[Math.floor((candidates.length - 1) / 2)].f;
}

async function PromiseRace(promises: Promise<any>[], keyType: string, amountRequired: number, customTimeout: number = null, customPromiseChecker: Function = null, promoteUnanimousCodes: boolean = false) {
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
        const fastestPromise: any = await Promise.race(racePromises);

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
        // Keep the existing developer-visible breadcrumb (per-error stacks
        // still print individually) so anyone debugging in DevTools can
        // expand each failure. The THROWN value, however, is now a single
        // aggregate TideError so callers (admin-ui, login pages, …) get one
        // structured thing to render instead of N opaque exceptions.
        if (failed.length > 0) {
            console.log("Errors in flow:");
            failed.forEach(f => console.error(f));
        }

        // Preserve the throttle special-case verbatim — admin-ui already
        // branches on this string to show the "too many attempts" toast.
        if (failed.some(ex => ex === "Too many attempts")) {
            throw new TideError({
                code: TideJsErrorCodes.NET_THRESHOLD_FAILURE,
                displayMessage: "enclave.throttled",
                source: "Tools/Utils.ts:PromiseRace",
                details: failed.map(_toDetail),
                cause: failed[0],
            });
        }

        const details = failed.map(_toDetail);
        const got = fullyCompletedPromises;
        const required = amountRequired;
        const totalAttempted = initLength;

        // Opt-in unanimous-code promotion (see WaitForORKsOptions). Must stay
        // AFTER the "Too many attempts" special case above (admin-ui
        // string-matches that path) and BEFORE the generic
        // NET_THRESHOLD_FAILURE throw below.
        // TRUE-unanimity gate: promotion requires the failure set to cover
        // the FULL attempted cohort. `failed.length === initLength` means
        // every attempted promise rejected — none succeeded (results would
        // hold it), none were still pending when the timeout truncated the
        // loop, and none resolved-but-failed a customPromiseChecker (those
        // land in results, not failed). `results.length === 0` is asserted
        // explicitly as belt-and-braces: any success whatsoever disqualifies
        // promotion. A partial set falls through to NET_THRESHOLD_FAILURE.
        if (
            promoteUnanimousCodes
            && failed.length > 0
            && failed.length === initLength
            && results.length === 0
            && failed.every(f => TideError.isTideError(f))
        ) {
            const tideFailed = failed as TideError[];
            const unanimousCode = tideFailed[0].code;
            const unanimous = tideFailed.every(f => f.code === unanimousCode);
            if (unanimous && !unanimousCode.startsWith("TIDE-TIDEJS-")) {
                // Representative = median of numeric `messageParams.minutes`
                // (values are STRINGS on the wire); fall back to median of
                // `expirySeconds` for older ORKs that still send it; else the
                // first failure. See _medianFailureByParam for the
                // honest-majority rationale.
                const representative =
                    _medianFailureByParam(tideFailed, "minutes")
                    ?? _medianFailureByParam(tideFailed, "expirySeconds")
                    ?? tideFailed[0];

                // Namespace guard: a PROMOTED messageKey may only select
                // entries from the Tide error catalog. The Enclave's
                // getTranslation resolves arbitrary dotted paths in its i18n
                // bundle, so an unguarded key would let a unanimous cohort
                // pick arbitrary catalog strings (social-engineering text).
                // Outside the namespace we omit the key; the Enclave then
                // falls back to displayMessage / code.
                const repKey = representative.messageKey;
                const promotedMessageKey =
                    typeof repKey === "string"
                        && (repKey.startsWith("error.tide.") || repKey.startsWith("errors.tide."))
                        ? repKey
                        : null;

                throw new TideError({
                    code: representative.code,
                    displayMessage: representative.displayMessage,
                    messageKey: promotedMessageKey,
                    messageParams: representative.messageParams,
                    httpStatus: representative.httpStatus,
                    problemType: representative.problemType,
                    traceId: representative.traceId,
                    source: `Tools/Utils.ts:PromiseRace (promoted: ${tideFailed.length} identical per-ORK failures)`,
                    details,
                    cause: representative,
                });
            }
        }

        if (failed.length > 0) {
            throw new TideError({
                code: TideJsErrorCodes.NET_THRESHOLD_FAILURE,
                displayMessage: `Could not reach enough ${keyType} ORKs (got ${got} of ${required} required, ${failed.length} of ${totalAttempted} failed)`,
                source: "Tools/Utils.ts:PromiseRace",
                details,
                cause: failed[0],
            });
        } else if (timeoutReached) {
            throw new TideError({
                code: TideJsErrorCodes.NET_THRESHOLD_FAILURE,
                displayMessage: `enclave.thresholdTimeoutFailure (got ${got} of ${required} required ${keyType} ORKs before timeout)`,
                source: "Tools/Utils.ts:PromiseRace",
                details,
            });
        } else {
            throw new TideError({
                code: TideJsErrorCodes.NET_THRESHOLD_FAILURE,
                displayMessage: `${keyType} ORKs for this account are down (got ${got} of ${required} required)`,
                source: "Tools/Utils.ts:PromiseRace",
                details,
            });
        }
    }
}


export async function WaitForNumberofORKs(orkList_Ref: OrkInfo[], pre_responses: Promise<any>[], keyType: string, amountRequired: number = Threshold, bitwise_p: (0 | 1)[] = null, optionalArray: any[] = null, customTimeout: number = null, customPromiseChecker: Function = null, opts?: WaitForORKsOptions){
    // See Utils.cs on Midgard Core for how this can be improved
    // Basically, you don't need indexes in the responses, just use .indexOf

    const unsortedResponses = await PromiseRace(pre_responses, keyType, amountRequired, customTimeout, customPromiseChecker, opts?.promoteUnanimousCodes === true);
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
	const cleanedResponses = sortedResponses.map((resp, idx) => {
		for(let key in resp){
			if(resp.hasOwnProperty(key) && key !== "index" && key !== "tag") return resp[key];
		}
		throw new TideError({
			code: TideJsErrorCodes.PARSE_NODECLIENT_RESPONSE_SHAPE,
			displayMessage: `WaitForThresholdNumberofORKs got unexpected response shape: keyType=${keyType}, index=${idx}, responseKeys=[${Object.keys(resp).join(',')}]`,
			source: "Tools/Utils.ts:250",
		});
	});
	return {fulfilledResponses: cleanedResponses, bitwise};
}
export function removeRandomElements(array: any[], targetArraySize: number): any[] {
    let newArray = array.slice();
    // Check if the array size is > n
    if (newArray.length < targetArraySize) {
        throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_LENGTH, displayMessage: `Array size must be greater than n (got length=${newArray.length}, target=${targetArraySize}).`, source: "tide-js/Tools/Utils.ts:262" });
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

export function sortORKs(orks: OrkInfo[]){
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
