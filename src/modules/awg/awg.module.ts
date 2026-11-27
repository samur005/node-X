import { Module } from '@nestjs/common';

import { AwgIntegrationModule } from '@integration-modules/awg/awg.integration';

import { AwgController } from './awg.controller';
import { AwgService } from './awg.service';

@Module({
    imports: [AwgIntegrationModule],
    controllers: [AwgController],
    providers: [AwgService],
})
export class AwgModule {}
