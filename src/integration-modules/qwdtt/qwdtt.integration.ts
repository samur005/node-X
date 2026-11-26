import type { IQwdttSidecarConfig } from './qwdtt.types';

import { Injectable, Logger, Module } from '@nestjs/common';

import {
    INodeIntegration,
    INodeIntegrationDescriptor,
    INodeIntegrationResult,
    INodeIntegrationStartOptions,
} from '../integrations.contract';
import { QwdttSupervisorService } from './qwdtt.supervisor';

export const QWDTT_INTEGRATION_KEY = 'qwdtt';

@Injectable()
export class QwdttIntegrationService implements INodeIntegration {
    public readonly name = QWDTT_INTEGRATION_KEY;
    private readonly logger = new Logger(QwdttIntegrationService.name);

    constructor(private readonly supervisor: QwdttSupervisorService) {}

    public async sync(options: INodeIntegrationStartOptions): Promise<INodeIntegrationResult> {
        const payload = this.readPayload(options.integrationConfig);
        if (!payload) {
            await this.supervisor.reconcile({
                enabled: false,
                listenAddr: '0.0.0.0:56000',
                wgPort: 56001,
                dns: '8.8.8.8',
                mainPassword: 'disabled',
                users: [],
            });
            return { error: null };
        }

        const { error } = await this.supervisor.reconcile(payload);
        if (error) {
            this.logger.error(`qWDTT sync failed: ${error}`);
        }
        return { error };
    }

    public async stop(): Promise<void> {
        await this.supervisor.reconcile({
            enabled: false,
            listenAddr: '0.0.0.0:56000',
            wgPort: 56001,
            dns: '8.8.8.8',
            mainPassword: 'disabled',
            users: [],
        });
    }

    private readPayload(config: Record<string, unknown>): IQwdttSidecarConfig | null {
        const raw = config[QWDTT_INTEGRATION_KEY];
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
            return null;
        }
        return raw as IQwdttSidecarConfig;
    }
}

@Module({
    providers: [QwdttSupervisorService, QwdttIntegrationService],
    exports: [QwdttSupervisorService, QwdttIntegrationService],
})
export class QwdttIntegrationModule {}

export const descriptor: INodeIntegrationDescriptor = {
    module: QwdttIntegrationModule,
    service: QwdttIntegrationService,
    isAvailable: () => true,
};
