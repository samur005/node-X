import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { sanitizeAwgSyncRequest } from './awg.types';

const PLACEHOLDER_SERVER = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const PLACEHOLDER_PEER_PUB = 'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=';
const PLACEHOLDER_CLIENT_PRIV = 'mZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZk=';

describe('sanitizeAwgSyncRequest', () => {
    it('strips a client private key if one is accidentally present on a peer', () => {
        const sanitized = sanitizeAwgSyncRequest({
            enabled: true,
            instance: {
                listenPort: 51820,
                privateKey: PLACEHOLDER_SERVER,
                subnet: '10.8.1.0/24',
                mtu: 0,
                dns: '1.1.1.1, 8.8.8.8',
                keepalive: 25,
                allowedIps: '0.0.0.0/0, ::/0',
                version: '2.0',
                obfuscation: {
                    jc: 4,
                    jmin: 40,
                    jmax: 90,
                    s1: 20,
                    s2: 30,
                    h1: '10',
                    h2: '20',
                    h3: '30',
                    h4: '40',
                },
            },
            peers: [
                {
                    publicKey: PLACEHOLDER_PEER_PUB,
                    address: '10.8.1.2',
                    // @ts-expect-error — the contract forbids this field
                    privateKey: PLACEHOLDER_CLIENT_PRIV,
                },
            ],
        });

        const encoded = JSON.stringify(sanitized);
        assert.equal('privateKey' in sanitized.peers[0], false);
        assert.equal(encoded.includes(PLACEHOLDER_CLIENT_PRIV), false);
        assert.equal(sanitized.peers[0].publicKey, PLACEHOLDER_PEER_PUB);
        assert.equal(sanitized.peers[0].address, '10.8.1.2');
        assert.equal(sanitized.instance?.privateKey, PLACEHOLDER_SERVER);
    });

    it('keeps an empty instance when the sidecar is disabled', () => {
        const sanitized = sanitizeAwgSyncRequest({
            enabled: false,
            instance: null,
            peers: [],
        });
        assert.equal(sanitized.enabled, false);
        assert.equal(sanitized.instance, null);
        assert.deepEqual(sanitized.peers, []);
    });
});
