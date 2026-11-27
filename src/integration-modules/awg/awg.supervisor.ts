import type { IAwgSidecarConfig, IAwgSidecarStatus } from './awg.types';

import { ChildProcess, spawn } from 'node:child_process';
import { accessSync, constants as fsConstants, promises as fs } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { Injectable, Logger, OnApplicationShutdown } from '@nestjs/common';

import { sanitizeAwgSyncRequest } from './awg.types';

export const DEFAULT_AWG_BIN = '/usr/local/bin/awg';
export const DEFAULT_AWG_CONFIG_DIR = '/var/lib/remnawave/awg';
export const ENV_AWG_BIN = 'AWG_BIN';
export const AWG_IFACE_NAME = 'rxawg0';

const STOP_GRACE_MS = 5_000;
const STOP_FORCE_MS = 2_000;
const RESTART_DELAY_MS = 5_000;

@Injectable()
export class AwgSupervisorService implements OnApplicationShutdown {
    private readonly logger = new Logger(AwgSupervisorService.name);

    private child: ChildProcess | null = null;
    private lastError = '';
    private lastExit = '';
    private enabled = false;
    private configDir = DEFAULT_AWG_CONFIG_DIR;
    private restartTimer: NodeJS.Timeout | null = null;
    private failStreak = 0;
    private stopping = false;
    private latestConfig: IAwgSidecarConfig | null = null;

    public binaryPath(): string {
        const fromEnv = process.env[ENV_AWG_BIN]?.trim();
        return fromEnv && fromEnv.length > 0 ? fromEnv : DEFAULT_AWG_BIN;
    }

    public binaryFound(): boolean {
        try {
            accessSync(this.binaryPath(), fsConstants.X_OK);
            return true;
        } catch {
            try {
                accessSync(this.binaryPath(), fsConstants.F_OK);
                return true;
            } catch {
                return false;
            }
        }
    }

    public resolveConfigDir(configDir?: string): string {
        const raw = configDir?.trim();
        if (!raw) {
            return DEFAULT_AWG_CONFIG_DIR;
        }
        return path.isAbsolute(raw) ? raw : path.resolve(raw);
    }

    public isRunning(): boolean {
        return Boolean(this.child?.pid) && this.child?.exitCode === null;
    }

    public async status(): Promise<IAwgSidecarStatus> {
        const file = await this.readStatusFile();
        const running = this.isRunning();
        return {
            supported: process.platform === 'linux',
            enabled: this.enabled,
            running,
            iface: file?.iface || AWG_IFACE_NAME,
            peers: file?.peers ?? 0,
            online: file?.online ?? 0,
            version: file?.version,
            egress: 'sidecar-nat',
            error: this.lastError || file?.error || undefined,
            lastExit: !running && this.lastExit ? this.lastExit : undefined,
        };
    }

    public async reconcile(config: IAwgSidecarConfig): Promise<{ error: string | null }> {
        const sanitized = sanitizeAwgSyncRequest(config);
        this.enabled = sanitized.enabled;
        this.configDir = this.resolveConfigDir(sanitized.configDir);
        this.latestConfig = sanitized;

        if (!sanitized.enabled) {
            await this.writeConfig(sanitized);
            await this.stop();
            this.lastError = '';
            this.failStreak = 0;
            return { error: null };
        }

        if (process.platform !== 'linux') {
            this.lastError = 'AWG is only supported on Linux';
            return { error: this.lastError };
        }

        try {
            await this.writeConfig(sanitized);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.lastError = `writing config.json: ${message}`;
            this.logger.error(this.lastError);
            return { error: this.lastError };
        }

        if (this.isRunning()) {
            this.sighup();
            this.lastError = '';
            this.failStreak = 0;
            return { error: null };
        }

        const startError = this.start();
        if (startError) {
            this.lastError = startError;
            return { error: startError };
        }

        this.lastError = '';
        this.failStreak = 0;
        return { error: null };
    }

    public async onApplicationShutdown(): Promise<void> {
        await this.stop();
    }

    private configPath(): string {
        return path.join(this.configDir, 'config.json');
    }

    private statusPath(): string {
        return path.join(this.configDir, 'status.json');
    }

    private async writeConfig(config: IAwgSidecarConfig): Promise<void> {
        await fs.mkdir(this.configDir, { recursive: true, mode: 0o700 });
        const body = JSON.stringify(
            {
                enabled: config.enabled,
                instance: config.instance,
                peers: config.peers,
            },
            null,
            2,
        );
        const tmp = `${this.configPath()}.tmp`;
        await fs.writeFile(tmp, `${body}\n`, { mode: 0o600 });
        await fs.rename(tmp, this.configPath());
    }

    private async readStatusFile(): Promise<Partial<IAwgSidecarStatus> | null> {
        try {
            const raw = await fs.readFile(this.statusPath(), 'utf8');
            const parsed = JSON.parse(raw) as Partial<IAwgSidecarStatus>;
            if (!parsed || typeof parsed !== 'object') {
                return null;
            }
            return parsed;
        } catch {
            return null;
        }
    }

    private start(): string | null {
        const bin = this.binaryPath();
        if (!this.binaryFound()) {
            const message = `awg: sidecar binary not found at ${bin}`;
            this.logger.warn(message);
            return message;
        }

        this.stopping = false;
        const child = spawn(bin, ['--config', this.configPath(), '--status', this.statusPath()], {
            stdio: ['ignore', 'pipe', 'pipe'],
            detached: false,
        });
        this.child = child;
        this.lastExit = '';

        child.stdout?.on('data', (buf: Buffer) => this.capture(buf));
        child.stderr?.on('data', (buf: Buffer) => this.capture(buf));
        child.on('error', (error) => {
            this.lastError = `awg: starting sidecar: ${error.message}`;
            this.logger.error(this.lastError);
        });
        child.on('exit', (code, signal) => {
            if (this.child === child) {
                this.child = null;
                this.lastExit = signal ? `signal ${signal}` : `exit ${code ?? '?'}`;
                if (!this.stopping) {
                    this.logger.warn(`awg: sidecar exited (${this.lastExit})`);
                    if (this.enabled && this.latestConfig) {
                        this.scheduleRestart(this.latestConfig);
                    }
                }
            }
        });

        this.logger.log(`awg: sidecar started (${bin}, iface ${AWG_IFACE_NAME})`);
        return null;
    }

    private sighup(): void {
        if (!this.child?.pid) {
            return;
        }
        try {
            process.kill(this.child.pid, 'SIGHUP');
            this.logger.log('awg: sent SIGHUP to reload config.json');
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger.warn(`awg: SIGHUP failed: ${message}`);
        }
    }

    private async stop(): Promise<void> {
        this.clearRestart();
        const child = this.child;
        if (!child?.pid || child.exitCode !== null) {
            this.child = null;
            return;
        }
        this.stopping = true;
        const pid = child.pid;
        const exited = new Promise<void>((resolve) => {
            const done = () => resolve();
            child.once('exit', done);
        });
        try {
            process.kill(pid, 'SIGTERM');
        } catch {
            this.child = null;
            return;
        }
        const timedOut = await this.wait(exited, STOP_GRACE_MS);
        if (timedOut) {
            try {
                process.kill(pid, 'SIGKILL');
            } catch {
                // already gone
            }
            await this.wait(exited, STOP_FORCE_MS);
        }
        this.child = null;
        this.stopping = false;
    }

    private scheduleRestart(config: IAwgSidecarConfig): void {
        this.clearRestart();
        this.failStreak += 1;
        const delay = RESTART_DELAY_MS * Math.min(this.failStreak, 6);
        this.restartTimer = setTimeout(() => {
            void this.reconcile(config);
        }, delay);
        this.restartTimer.unref();
    }

    private clearRestart(): void {
        if (this.restartTimer) {
            clearTimeout(this.restartTimer);
            this.restartTimer = null;
        }
    }

    private capture(buf: Buffer): void {
        for (const line of buf.toString('utf8').split('\n')) {
            const trimmed = line.trim();
            if (!trimmed) {
                continue;
            }
            this.logger.log(`awg | ${trimmed}`);
        }
    }

    private async wait(promise: Promise<void>, ms: number): Promise<boolean> {
        let timer: NodeJS.Timeout | undefined;
        const timeout = new Promise<boolean>((resolve) => {
            timer = setTimeout(() => resolve(true), ms);
        });
        const result = await Promise.race([promise.then(() => false), timeout]);
        if (timer) {
            clearTimeout(timer);
        }
        return result;
    }
}
