import Tide from "../dist/main";
import config from "./test-config"

const tide = new Tide(config.nodes, 32)

const keys = {
    pub: "AJra1cjNkuhygof9/Gs7eQs6XZVlVp4eEnCywvGtpJmbLAp+NBHpVLSGLv7Bu8VbinESeSuvgyrSshz34OaIXNAQPuj+Y8KtXiin4MQUnO81DtIHxO3XzaU4rDZfSve0Vg==",
    priv: "Apra1cjNkuhygof9/Gs7eQs6XZVlVp4eEnCywvGtpJmbLAp+NBHpVLSGLv7Bu8VbinESeSuvgyrSshz34OaIXNAL6UWLN+1dEWPpQKKSv6C13j2BGK4DV2n1lax18mYKhg=="
};


async function encryption() {
    const secretMsg = "This is a test";
    const encrypted = await tide.processEncryption(true, secretMsg, keys.pub);
    console.log(encrypted);

    const decrypted = await tide.processEncryption(false, encrypted, keys.priv);
    console.log(decrypted)
}

encryption();