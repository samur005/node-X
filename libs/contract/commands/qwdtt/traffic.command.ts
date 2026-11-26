import { z } from 'zod';

import { REST_API } from '../../api';

export const QwdttTrafficEntrySchema = z.object({
    password: z.string(),
    label: z.string().optional(),
    upBytes: z.number().int().nonnegative(),
    downBytes: z.number().int().nonnegative(),
    deviceCount: z.number().int().nonnegative(),
    isDeactivated: z.boolean(),
});

export namespace GetQwdttTrafficCommand {
    export const url = REST_API.QWDTT.TRAFFIC;

    export const ResponseSchema = z.object({
        response: z.object({
            users: z.array(QwdttTrafficEntrySchema),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
