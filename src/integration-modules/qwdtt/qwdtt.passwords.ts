import type {
    IQwdttPasswordEntry,
    ISidecarDatabase,
    ISidecarPasswordEntry,
    IQwdttTrafficEntry,
} from './qwdtt.types';

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const PASSWORDS_FILE = 'passwords.json';

function emptyDb(): ISidecarDatabase {
    return { passwords: {}, devices: {} };
}

export async function readPasswordsFile(configDir: string): Promise<ISidecarDatabase> {
    const file = path.join(configDir, PASSWORDS_FILE);
    try {
        const raw = await readFile(file, 'utf8');
        const parsed = JSON.parse(raw) as Partial<ISidecarDatabase>;
        return {
            passwords: parsed.passwords ?? {},
            devices: parsed.devices ?? {},
        };
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
            return emptyDb();
        }
        throw error;
    }
}

/**
 * Merge panel-managed user passwords into passwords.json without dropping
 * sidecar-owned device records or cumulative traffic counters. The sidecar
 * reloads this file on SIGHUP.
 *
 * The file format follows SpaceNeuroX/proxy-turn-vk-android (GPL-3.0)
 * passwords.json (PasswordEntry / Database). MainPassword is not stored
 * in the file (the sidecar marks it json:"-").
 */
export function deviceBelongsToEntry(entry: ISidecarPasswordEntry, deviceId: string): boolean {
    return entry.device_ids?.includes(deviceId) || entry.device_id === deviceId;
}

export function mergePasswordEntries(
    existing: ISidecarDatabase,
    users: IQwdttPasswordEntry[],
): ISidecarDatabase {
    const nextPasswords: Record<string, ISidecarPasswordEntry> = {};

    for (const user of users) {
        const prev = existing.passwords[user.password];
        nextPasswords[user.password] = {
            label: user.label ?? user.username,
            device_id: prev?.device_id ?? '',
            device_ids: prev?.device_ids ?? [],
            max_devices: user.maxDevices ?? prev?.max_devices ?? 0,
            expires_at: user.expiresAt ?? prev?.expires_at ?? 0,
            down_bytes: prev?.down_bytes ?? 0,
            up_bytes: prev?.up_bytes ?? 0,
            is_deactivated: user.isDeactivated ?? false,
        };
    }

    const nextDevices: ISidecarDatabase['devices'] = {};
    for (const [id, device] of Object.entries(existing.devices)) {
        const kept = Object.values(nextPasswords).some((entry) => deviceBelongsToEntry(entry, id));
        const wasAttached = Object.values(existing.passwords).some((entry) =>
            deviceBelongsToEntry(entry, id),
        );
        if (kept || !wasAttached) {
            nextDevices[id] = device;
        }
    }

    return { passwords: nextPasswords, devices: nextDevices };
}

export async function writePasswordsFile(configDir: string, db: ISidecarDatabase): Promise<string> {
    await mkdir(configDir, { mode: 0o700, recursive: true });
    const file = path.join(configDir, PASSWORDS_FILE);
    const tmp = path.join(configDir, `.passwords-${process.pid}.tmp`);
    await writeFile(tmp, `${JSON.stringify(db, null, 2)}\n`, { mode: 0o600 });
    await rename(tmp, file);
    return file;
}

export function trafficFromDatabase(db: ISidecarDatabase): IQwdttTrafficEntry[] {
    return Object.entries(db.passwords).map(([password, entry]) => ({
        password,
        label: entry.label,
        upBytes: entry.up_bytes ?? 0,
        downBytes: entry.down_bytes ?? 0,
        deviceCount: entry.device_ids?.length || (entry.device_id ? 1 : 0),
        isDeactivated: Boolean(entry.is_deactivated),
    }));
}
