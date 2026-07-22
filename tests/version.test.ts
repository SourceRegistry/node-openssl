import {test, expect} from 'vitest';
import {openssl} from '../src';

test('OpenSSL version is parsed from `openssl version` output', () => {
    expect(openssl.version.major).toBeGreaterThanOrEqual(1);
    expect(Number.isInteger(openssl.version.minor)).toBe(true);
    expect(Number.isInteger(openssl.version.patch)).toBe(true);
    expect(openssl.version.release_date.length).toBeGreaterThan(0);
    expect(openssl.version.lib.major).toBeGreaterThanOrEqual(1);
});
