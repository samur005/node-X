import type { ISidecarDatabase } from './qwdtt.types';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { mergePasswordEntries, trafficFromDatabase } from './qwdtt.passwords';

describe('mergePasswordEntries', () => {
    it('preserves traffic and devices when the same password is updated', () => {
        const existing: ISidecarDatabase = {
            passwords: {
                secretA: {
                    label: 'alice',
                    device_id: 'dev-1',
                    device_ids: ['dev-1'],
                    max_devices: 1,
                    expires_at: 0,
                    down_bytes: 1000,
                    up_bytes: 2000,
                },
            },
            devices: {
                'dev-1': {
                    device_id: 'dev-1',
                    ip: '10.68.0.2',
                    priv_key: 'p',
                    pub_key: 'k',
                    down_bytes: 1000,
                    up_bytes: 2000,
                },
            },
        };

        const merged = mergePasswordEntries(existing, [
            {
                username: 'alice',
                password: 'secretA',
                label: 'alice',
                maxDevices: 3,
                expiresAt: 1_700_000_000,
                isDeactivated: false,
            },
        ]);

        assert.equal(merged.passwords.secretA.down_bytes, 1000);
        assert.equal(merged.passwords.secretA.up_bytes, 2000);
        assert.deepEqual(merged.passwords.secretA.device_ids, ['dev-1']);
        assert.equal(merged.passwords.secretA.max_devices, 3);
        assert.equal(merged.passwords.secretA.expires_at, 1_700_000_000);
        assert.ok(merged.devices['dev-1']);
    });

    it('drops devices of a removed password and keeps unrelated leftovers', () => {
        const existing: ISidecarDatabase = {
            passwords: {
                gone: {
                    label: 'bob',
                    device_id: 'dev-2',
                    device_ids: ['dev-2'],
                    max_devices: 1,
                    expires_at: 0,
                    down_bytes: 5,
                    up_bytes: 6,
                },
            },
            devices: {
                'dev-2': {
                    device_id: 'dev-2',
                    ip: '10.68.0.3',
                    priv_key: 'p',
                    pub_key: 'k',
                    down_bytes: 5,
                    up_bytes: 6,
                },
                leftover: {
                    device_id: 'leftover',
                    ip: '10.68.0.4',
                    priv_key: 'p',
                    pub_key: 'k',
                    down_bytes: 1,
                    up_bytes: 1,
                },
            },
        };

        const merged = mergePasswordEntries(existing, [
            { username: 'alice', password: 'secretA', label: 'alice' },
        ]);

        assert.equal(merged.passwords.gone, undefined);
        assert.equal(merged.devices['dev-2'], undefined);
        assert.ok(merged.devices.leftover);
        assert.equal(merged.passwords.secretA.label, 'alice');
        assert.equal(merged.passwords.secretA.down_bytes, 0);
    });
});

describe('trafficFromDatabase', () => {
    it('maps sidecar counters to panel traffic entries', () => {
        const rows = trafficFromDatabase({
            passwords: {
                p1: {
                    label: 'alice',
                    device_ids: ['a', 'b'],
                    max_devices: 2,
                    expires_at: 0,
                    down_bytes: 10,
                    up_bytes: 20,
                    is_deactivated: true,
                },
            },
            devices: {},
        });
        assert.deepEqual(rows, [
            {
                password: 'p1',
                label: 'alice',
                upBytes: 20,
                downBytes: 10,
                deviceCount: 2,
                isDeactivated: true,
            },
        ]);
    });
});
