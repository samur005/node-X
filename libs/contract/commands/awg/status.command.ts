/**
 * AWG node status contract. The sidecar reports running, iface, peers and online.
 *
 * Combined Remnawave X work is AGPL-3.0-only. v1 status is running, iface,
 * peers and online — not per-client traffic counters.
 */
import { z } from 'zod';

import { REST_API } from '../../api';

export namespace GetAwgStatusCommand {
    export const url = REST_API.AWG.STATUS;

    export const ResponseSchema = z.object({
        response: z.object({
            supported: z.boolean(),
            enabled: z.boolean(),
            running: z.boolean(),
            iface: z.string(),
            peers: z.number().int(),
            online: z.number().int(),
            version: z.string().optional(),
            egress: z.literal('sidecar-nat'),
            error: z.string().optional(),
            lastExit: z.string().optional(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
