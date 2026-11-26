export interface IQwdttPasswordEntry {
    username: string;
    password: string;
    label?: string;
    maxDevices?: number;
    expiresAt?: number;
    isDeactivated?: boolean;
}

export interface IQwdttSidecarConfig {
    enabled: boolean;
    listenAddr: string;
    wgPort: number;
    dns: string;
    listenRaw?: string;
    listenDirect?: string;
    mainPassword: string;
    configDir?: string;
    users: IQwdttPasswordEntry[];
}

export interface ISidecarPasswordEntry {
    label?: string;
    device_id?: string;
    device_ids?: string[];
    max_devices: number;
    expires_at: number;
    down_bytes: number;
    up_bytes: number;
    is_deactivated?: boolean;
}

export interface ISidecarDevice {
    device_id: string;
    ip: string;
    priv_key: string;
    pub_key: string;
    down_bytes: number;
    up_bytes: number;
    owner_id?: string;
    raw_ip?: string;
    raw_owner_id?: string;
}

export interface ISidecarDatabase {
    passwords: Record<string, ISidecarPasswordEntry>;
    devices: Record<string, ISidecarDevice>;
}

export interface IQwdttTrafficEntry {
    password: string;
    label?: string;
    upBytes: number;
    downBytes: number;
    deviceCount: number;
    isDeactivated: boolean;
}
