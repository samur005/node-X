import { Body, Controller, Get, Post, UseFilters, UseGuards } from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { QWDTT_CONTROLLER, QWDTT_ROUTES } from '@libs/contracts/api';
import { SyncQwdttCommand } from '@libs/contracts/commands';

import { QwdttService } from './qwdtt.service';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller(QWDTT_CONTROLLER)
export class QwdttController {
    constructor(private readonly qwdttService: QwdttService) {}

    @Post(QWDTT_ROUTES.SYNC)
    public async sync(@Body() body: SyncQwdttCommand.Request) {
        const response = await this.qwdttService.sync(body);
        return { response };
    }

    @Get(QWDTT_ROUTES.STATUS)
    public async status() {
        const response = await this.qwdttService.status();
        return { response };
    }

    @Get(QWDTT_ROUTES.TRAFFIC)
    public async traffic() {
        const response = await this.qwdttService.traffic();
        return { response };
    }
}
