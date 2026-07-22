import {test, expect} from 'vitest';
import {OpenSSL} from '../src';

const CERT = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n';
const KEY = '-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n';

test('AnalysePEM detects the PEM type', () => {
    expect(OpenSSL.AnalysePEM(CERT).type).toBe('CERTIFICATE');
    expect(OpenSSL.AnalysePEM(KEY).type).toBe('PRIVATE KEY');
    expect(OpenSSL.AnalysePEM('not pem data').type).toBe('Unknown');
});

test('AnalysePEM only flags a chain when multiple certificates are present', () => {
    const single = OpenSSL.AnalysePEM(CERT);
    expect(single.isChain).toBe(false);
    expect(single.certificates).toEqual([]);

    const chain = OpenSSL.AnalysePEM(CERT + CERT);
    expect(chain.isChain).toBe(true);
    expect(chain.certificates.length).toBe(2);
});
