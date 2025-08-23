import {openssl} from "../src";

async function main() {
    //Digest buffer and output digest;
    const data = Buffer.from("Helloworld")
    const digested = await openssl`dgst -sha256 ${data}`.one();
    console.log(digested.toString('utf-8').split("=")[1].trim()) //(Not ideal yet)
}

main().catch(console.error);
