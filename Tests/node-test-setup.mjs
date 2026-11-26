// Registers the extension-appending ESM resolver before tests import dist/.
// Used via: node --import ./Tests/node-test-setup.mjs --test <test files>
import { register } from "node:module";

register(new URL("./node-esm-extension-loader.mjs", import.meta.url));
