import {test, expect} from 'vitest';
import {readdir, stat} from 'fs/promises';
import {tmpdir} from 'os';
import {join} from 'path';
import {randomUUID} from 'crypto';
import {openssl, OpenSSL} from '../src';

test('digests a Buffer passed as a standalone interpolated value', async () => {
    const data = Buffer.from('Helloworld');
    const digested = await openssl`dgst -sha256 ${data}`.one();
    const hex = digested.toString('utf-8').split('=')[1].trim();
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
});

test('generates an RSA key and a self-signed certificate signed with it', async () => {
    const key = await openssl`genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:2048`.one();
    expect(key.type).toBe('PRIVATE KEY');

    const cert = await openssl`req -x509 -new -key ${key} -subj "/CN=localhost" -days 365 -outform PEM`.one();
    expect(cert.type).toBe('CERTIFICATE');
    expect(cert.isChain).toBe(false);
    expect(cert.sha256).toMatch(/^[A-Za-z0-9_-]+$/);
}, 15000);

test('rejects with an OpenSSLError when the command fails, instead of throwing a raw error', async () => {
    await expect(openssl`this-is-not-a-real-subcommand`).rejects.toSatisfy((err: unknown) => OpenSSL.isOpenSSLError(err));
});

test('a value interpolated into a quoted argument cannot break out and run another command', async () => {
    // Regression test for the command-injection issue fixed by switching exec() from a
    // shell-joined string to execFile() with a real argv array: an interpolated value used to be
    // able to terminate the quoted -subj value and append arbitrary shell commands.
    const marker = join(tmpdir(), `injection-marker-${randomUUID()}`);
    const malicious = `/CN=x"; touch ${marker} #`;

    await openssl`req -x509 -new -newkey rsa:2048 -nodes -subj "${malicious}" -days 1 -outform PEM`
        .catch(() => {
        });

    await expect(stat(marker)).rejects.toThrow();
});

test('does not leave temp working directories (and the input files inside them, e.g. private keys) behind', async () => {
    const before = new Set(await readdir(tmpdir()));

    const key = await openssl`genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:2048`.one();
    await openssl`rsa -in ${key} -pubout`.one();

    const after = await readdir(tmpdir());
    const leaked = after.filter((f) => f.startsWith('openssl-') && !before.has(f));
    expect(leaked).toEqual([]);
}, 15000);
