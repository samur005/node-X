import { z } from 'zod';

import { REST_API } from '../../api';

export const QwdttPasswordEntrySchema = z.object({
    username: z.string(),
    password: z.string().min(1),
    label: z.string().optional(),
    maxDevices: z.number().int().nonnegative().optional(),
    expiresAt: z.number().int().nonnegative().optional(),
    isDeactivated: z.boolean().optional(),
});

export const QwdttSidecarConfigSchema = z.object({
    enabled: z.boolean(),
    listenAddr: z.string(),
    wgPort: z.number().int(),
    dns: z.string(),
    listenRaw: z.string().optional().default(''),
    listenDirect: z.string().optional().default(''),
    mainPassword: z.string().min(1),
    configDir: z.string().optional(),
});

export const QwdttSyncPayloadSchema = QwdttSidecarConfigSchema.extend({
    users: z.array(QwdttPasswordEntrySchema),
});

export namespace SyncQwdttCommand {
    export const url = REST_API.QWDTT.SYNC;

    export const RequestSchema = QwdttSyncPayloadSchema;

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            error: z.string().nullable(),
            running: z.boolean(),
            pid: z.number().int(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
