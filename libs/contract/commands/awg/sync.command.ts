/**
 * Draft AWG node sync contract. The sidecar is not implemented in this phase.
 *
 * Combined Remnawave X work is AGPL-3.0-only. Field names follow
 * samur005/3s-ui wgserver.Config and Obfuscation (GPL-3.0).
 *
 * The node receives the server private key and peer public keys, plus
 * PSK and the peer IPv4 /32. Client private keys must never appear here.
 */
import { z } from 'zod';

import { REST_API } from '../../api';

export const AwgObfuscationSchema = z.object({
    jc: z.number().int(),
    jmin: z.number().int(),
    jmax: z.number().int(),
    s1: z.number().int(),
    s2: z.number().int(),
    s3: z.number().int().optional(),
    s4: z.number().int().optional(),
    h1: z.string(),
    h2: z.string(),
    h3: z.string(),
    h4: z.string(),
    i1: z.string().optional(),
    i2: z.string().optional(),
    i3: z.string().optional(),
    i4: z.string().optional(),
    i5: z.string().optional(),
    headerProtectionKey: z.string().optional(),
    contentPaddingAddition: z.string().optional(),
    rekeyAfterTime: z.string().optional(),
    rekeyTimeout: z.string().optional(),
    rejectAfterTime: z.string().optional(),
    keepaliveTimeout: z.string().optional(),
    maxHandshakeAttempts: z.string().optional(),
    randomTrailers: z.boolean().optional(),
    disableCookies: z.boolean().optional(),
});

export const AwgInstanceSchema = z.object({
    listenPort: z.number().int(),
    listen: z.string().optional(),
    privateKey: z.string().min(1),
    publicKey: z.string().optional(),
    subnet: z.string(),
    mtu: z.number().int(),
    dns: z.string(),
    keepalive: z.number().int(),
    allowedIps: z.string(),
    endpoint: z.string().optional(),
    version: z.string(),
    obfuscation: AwgObfuscationSchema,
});

export const AwgPeerEntrySchema = z.object({
    publicKey: z.string().min(1),
    presharedKey: z.string().optional(),
    address: z.string().min(1),
    enabled: z.boolean().optional(),
});

export const AwgSyncPayloadSchema = z.object({
    enabled: z.boolean(),
    instance: AwgInstanceSchema.nullable(),
    peers: z.array(AwgPeerEntrySchema),
});

export namespace SyncAwgCommand {
    export const url = REST_API.AWG.SYNC;

    export const RequestSchema = AwgSyncPayloadSchema;

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            error: z.string().nullable(),
            running: z.boolean(),
            iface: z.string(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
