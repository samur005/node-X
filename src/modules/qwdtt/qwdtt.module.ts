import { Module } from '@nestjs/common';

import { QwdttIntegrationModule } from '@integration-modules/qwdtt/qwdtt.integration';

import { QwdttController } from './qwdtt.controller';
import { QwdttService } from './qwdtt.service';

@Module({
    imports: [QwdttIntegrationModule],
    controllers: [QwdttController],
    providers: [QwdttService],
})
export class QwdttModule {}
