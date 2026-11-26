import { z } from 'zod';

import { REST_API } from '../../api';

export namespace GetQwdttStatusCommand {
    export const url = REST_API.QWDTT.STATUS;

    export const ResponseSchema = z.object({
        response: z.object({
            supported: z.boolean(),
            enabled: z.boolean(),
            running: z.boolean(),
            pid: z.number().int(),
            uptime: z.number().int(),
            binary: z.string(),
            binaryFound: z.boolean(),
            egress: z.literal('sidecar-nat'),
            error: z.string().optional(),
            lastExit: z.string().optional(),
            logs: z.array(z.string()),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
