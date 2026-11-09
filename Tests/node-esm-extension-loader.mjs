// Node ESM resolver hook for running the compiled `dist/` output under
// `node --test`. tsc (moduleResolution: "bundler") emits extensionless
// relative specifiers (e.g. `import ... from "../Errors/TideError"`), which
// browsers-via-bundlers accept but plain Node ESM does not. This hook retries
// failed relative resolutions with `.js` (then `/index.js`) appended.
//
// Registered by node-test-setup.mjs — see the `test` script in package.json.
export async function resolve(specifier, context, nextResolve) {
    try {
        return await nextResolve(specifier, context);
    } catch (err) {
        if (
            (specifier.startsWith("./") || specifier.startsWith("../"))
            && !specifier.endsWith(".js") && !specifier.endsWith(".mjs")
        ) {
            try {
                return await nextResolve(specifier + ".js", context);
            } catch {
                return await nextResolve(specifier + "/index.js", context);
            }
        }
        throw err;
    }
}
