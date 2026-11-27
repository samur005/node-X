import type { IAwgSidecarConfig } from './awg.types';

import { Injectable, Logger, Module } from '@nestjs/common';

import {
    INodeIntegration,
    INodeIntegrationDescriptor,
    INodeIntegrationResult,
    INodeIntegrationStartOptions,
} from '../integrations.contract';
import { AwgSupervisorService } from './awg.supervisor';
import { sanitizeAwgSyncRequest } from './awg.types';

export const AWG_INTEGRATION_KEY = 'awg';

@Injectable()
export class AwgIntegrationService implements INodeIntegration {
    public readonly name = AWG_INTEGRATION_KEY;
    private readonly logger = new Logger(AwgIntegrationService.name);

    constructor(private readonly supervisor: AwgSupervisorService) {}

    public async sync(options: INodeIntegrationStartOptions): Promise<INodeIntegrationResult> {
        const payload = this.readPayload(options.integrationConfig);
        if (!payload) {
            await this.supervisor.reconcile({
                enabled: false,
                instance: null,
                peers: [],
            });
            return { error: null };
        }

        const { error } = await this.supervisor.reconcile(payload);
        if (error) {
            this.logger.error(`AWG sync failed: ${error}`);
        }
        return { error };
    }

    public async stop(): Promise<void> {
        await this.supervisor.reconcile({
            enabled: false,
            instance: null,
            peers: [],
        });
    }

    private readPayload(config: Record<string, unknown>): IAwgSidecarConfig | null {
        const raw = config[AWG_INTEGRATION_KEY];
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
            return null;
        }
        return sanitizeAwgSyncRequest(raw as IAwgSidecarConfig);
    }
}

@Module({
    providers: [AwgSupervisorService, AwgIntegrationService],
    exports: [AwgSupervisorService, AwgIntegrationService],
})
export class AwgIntegrationModule {}

export const descriptor: INodeIntegrationDescriptor = {
    module: AwgIntegrationModule,
    service: AwgIntegrationService,
    isAvailable: () => true,
};
