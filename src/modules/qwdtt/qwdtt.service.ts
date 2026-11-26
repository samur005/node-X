import { Injectable } from '@nestjs/common';

import { SyncQwdttCommand } from '@libs/contracts/commands';

import { QwdttSupervisorService } from '@integration-modules/qwdtt/qwdtt.supervisor';

@Injectable()
export class QwdttService {
    constructor(private readonly supervisor: QwdttSupervisorService) {}

    public async sync(body: SyncQwdttCommand.Request) {
        const { error } = await this.supervisor.reconcile(body);
        const status = this.supervisor.status();
        return {
            error,
            running: status.running,
            pid: status.pid,
        };
    }

    public async status() {
        return this.supervisor.status();
    }

    public async traffic() {
        return { users: await this.supervisor.traffic() };
    }
}
