import { Injectable } from '@nestjs/common';

import { SyncAwgCommand } from '@libs/contracts/commands';

import { AwgSupervisorService } from '@integration-modules/awg/awg.supervisor';
import { sanitizeAwgSyncRequest } from '@integration-modules/awg/awg.types';

@Injectable()
export class AwgService {
    constructor(private readonly supervisor: AwgSupervisorService) {}

    public async sync(body: SyncAwgCommand.Request) {
        const { error } = await this.supervisor.reconcile(sanitizeAwgSyncRequest(body));
        const status = await this.supervisor.status();
        return {
            error,
            running: status.running,
            iface: status.iface,
        };
    }

    public async status() {
        return this.supervisor.status();
    }
}
