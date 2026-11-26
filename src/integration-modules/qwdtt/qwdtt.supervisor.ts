import type { IQwdttSidecarConfig, IQwdttTrafficEntry } from './qwdtt.types';

import { ChildProcess, spawn } from 'node:child_process';
import { accessSync, constants as fsConstants } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { Injectable, Logger, OnApplicationShutdown } from '@nestjs/common';

import {
    readPasswordsFile,
    trafficFromDatabase,
    writePasswordsFile,
    mergePasswordEntries,
} from './qwdtt.passwords';

export const DEFAULT_QWDTT_BIN = '/usr/local/bin/qwdtt';
export const DEFAULT_QWDTT_CONFIG_DIR = '/var/lib/remnawave/qwdtt';
export const ENV_QWDTT_BIN = 'QWDTT_BIN';

const MAX_LOG_LINES = 500;
const STOP_GRACE_MS = 5_000;
const STOP_FORCE_MS = 2_000;
const RESTART_DELAY_MS = 5_000;

@Injectable()
export class QwdttSupervisorService implements OnApplicationShutdown {
    private readonly logger = new Logger(QwdttSupervisorService.name);

    private child: ChildProcess | null = null;
    private startedAt: number | null = null;
    private argsFingerprint = '';
    private lastError = '';
    private lastExit = '';
    private enabled = false;
    private configDir = DEFAULT_QWDTT_CONFIG_DIR;
    private restartTimer: NodeJS.Timeout | null = null;
    private failStreak = 0;
    private readonly logs: string[] = [];
    private stopping = false;

    public binaryPath(): string {
        const fromEnv = process.env[ENV_QWDTT_BIN]?.trim();
        return fromEnv && fromEnv.length > 0 ? fromEnv : DEFAULT_QWDTT_BIN;
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

    public status() {
        const running = this.isRunning();
        return {
            supported: process.platform === 'linux',
            enabled: this.enabled,
            running,
            pid: running && this.child?.pid ? this.child.pid : 0,
            uptime:
                running && this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0,
            binary: this.binaryPath(),
            binaryFound: this.binaryFound(),
            egress: 'sidecar-nat' as const,
            error: this.lastError || undefined,
            lastExit: !running && this.lastExit ? this.lastExit : undefined,
            logs: this.logs.slice(-100),
        };
    }

    public isRunning(): boolean {
        return Boolean(this.child?.pid) && this.child?.exitCode === null;
    }

    public async traffic(): Promise<IQwdttTrafficEntry[]> {
        const db = await readPasswordsFile(this.configDir);
        return trafficFromDatabase(db);
    }

    public async reconcile(config: IQwdttSidecarConfig): Promise<{ error: string | null }> {
        this.enabled = config.enabled;
        this.configDir = config.configDir?.trim() || DEFAULT_QWDTT_CONFIG_DIR;

        if (!config.enabled) {
            await this.stop();
            this.lastError = '';
            this.failStreak = 0;
            return { error: null };
        }

        if (process.platform !== 'linux') {
            this.lastError = 'qWDTT is only supported on Linux';
            return { error: this.lastError };
        }

        try {
            await this.writeUsers(config);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.lastError = `writing passwords.json: ${message}`;
            this.logger.error(this.lastError);
            return { error: this.lastError };
        }

        const args = this.buildArgs(config);
        const fingerprint = args.join('\0');
        const changed = this.argsFingerprint !== fingerprint;

        if (this.isRunning() && changed) {
            await this.stop();
        }

        if (this.isRunning()) {
            this.sighup();
            this.lastError = '';
            this.failStreak = 0;
            return { error: null };
        }

        const startError = this.start(args);
        if (startError) {
            this.lastError = startError;
            this.scheduleRestart(config);
            return { error: startError };
        }

        this.argsFingerprint = fingerprint;
        this.lastError = '';
        return { error: null };
    }

    public async onApplicationShutdown(): Promise<void> {
        await this.stop();
    }

    private async writeUsers(config: IQwdttSidecarConfig): Promise<void> {
        const existing = await readPasswordsFile(this.configDir);
        const merged = mergePasswordEntries(existing, config.users ?? []);
        await writePasswordsFile(this.configDir, merged);
    }

    private buildArgs(config: IQwdttSidecarConfig): string[] {
        const args = [
            '-listen',
            config.listenAddr,
            '-wg-port',
            String(config.wgPort),
            '-config-dir',
            this.configDir,
            '-password',
            config.mainPassword,
        ];
        if (config.dns?.trim()) {
            args.push('-dns', config.dns.trim());
        }
        if (config.listenRaw?.trim()) {
            args.push('-listen-raw', config.listenRaw.trim());
        }
        if (config.listenDirect?.trim()) {
            args.push('-listen-direct', config.listenDirect.trim());
        }
        return args;
    }

    private start(args: string[]): string | null {
        const bin = this.binaryPath();
        if (!this.binaryFound()) {
            const message = `qwdtt: server binary not found at ${bin}`;
            this.logger.warn(message);
            return message;
        }

        this.stopping = false;
        const child = spawn(bin, args, {
            stdio: ['ignore', 'pipe', 'pipe'],
            detached: false,
        });
        this.child = child;
        this.startedAt = Date.now();
        this.lastExit = '';

        child.stdout?.on('data', (buf: Buffer) => this.capture(buf));
        child.stderr?.on('data', (buf: Buffer) => this.capture(buf));
        child.on('error', (error) => {
            this.lastError = `qwdtt: starting server: ${error.message}`;
            this.logger.error(this.lastError);
        });
        child.on('exit', (code, signal) => {
            if (this.child === child) {
                this.child = null;
                this.startedAt = null;
                this.lastExit = signal ? `signal ${signal}` : `exit ${code ?? '?'}`;
                if (!this.stopping) {
                    this.logger.warn(`qwdtt: server exited (${this.lastExit})`);
                }
            }
        });

        this.logger.log(`qwdtt: server started (${bin})`);
        return null;
    }

    private sighup(): void {
        if (!this.child?.pid) {
            return;
        }
        try {
            process.kill(this.child.pid, 'SIGHUP');
            this.logger.log('qwdtt: sent SIGHUP to reload passwords.json');
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger.warn(`qwdtt: SIGHUP failed: ${message}`);
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
        this.startedAt = null;
        this.stopping = false;
    }

    private scheduleRestart(config: IQwdttSidecarConfig): void {
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
            this.logs.push(trimmed);
            if (this.logs.length > MAX_LOG_LINES) {
                this.logs.splice(0, this.logs.length - MAX_LOG_LINES);
            }
            this.logger.log(`qwdtt | ${trimmed}`);
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

    public resolveConfigDir(configDir?: string): string {
        const raw = configDir?.trim();
        if (!raw) {
            return DEFAULT_QWDTT_CONFIG_DIR;
        }
        return path.isAbsolute(raw) ? raw : path.resolve(raw);
    }
}
