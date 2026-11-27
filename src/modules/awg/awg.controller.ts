import { Body, Controller, Get, Post, UseFilters, UseGuards } from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { AWG_CONTROLLER, AWG_ROUTES } from '@libs/contracts/api';
import { SyncAwgCommand } from '@libs/contracts/commands';

import { AwgService } from './awg.service';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller(AWG_CONTROLLER)
export class AwgController {
    constructor(private readonly awgService: AwgService) {}

    @Post(AWG_ROUTES.SYNC)
    public async sync(@Body() body: SyncAwgCommand.Request) {
        const response = await this.awgService.sync(body);
        return { response };
    }

    @Get(AWG_ROUTES.STATUS)
    public async status() {
        const response = await this.awgService.status();
        return { response };
    }
}
