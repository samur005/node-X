export interface IAwgObfuscation {
    jc: number;
    jmin: number;
    jmax: number;
    s1: number;
    s2: number;
    s3?: number;
    s4?: number;
    h1: string;
    h2: string;
    h3: string;
    h4: string;
    i1?: string;
    i2?: string;
    i3?: string;
    i4?: string;
    i5?: string;
    headerProtectionKey?: string;
    contentPaddingAddition?: string;
    rekeyAfterTime?: string;
    rekeyTimeout?: string;
    rejectAfterTime?: string;
    keepaliveTimeout?: string;
    maxHandshakeAttempts?: string;
    randomTrailers?: boolean;
    disableCookies?: boolean;
}

export interface IAwgInstance {
    listenPort: number;
    listen?: string;
    privateKey: string;
    publicKey?: string;
    subnet: string;
    mtu: number;
    dns: string;
    keepalive: number;
    allowedIps: string;
    endpoint?: string;
    version: string;
    obfuscation: IAwgObfuscation;
}

export interface IAwgPeerEntry {
    publicKey: string;
    presharedKey?: string;
    address: string;
    enabled?: boolean;
}

export interface IAwgSidecarConfig {
    enabled: boolean;
    instance: IAwgInstance | null;
    peers: IAwgPeerEntry[];
    configDir?: string;
}

export interface IAwgSidecarStatus {
    supported: boolean;
    enabled: boolean;
    running: boolean;
    iface: string;
    peers: number;
    online: number;
    version?: string;
    egress: 'sidecar-nat';
    error?: string;
    lastExit?: string;
}

/**
 * Drop any unexpected fields (especially a client privateKey) before the
 * payload is written to disk or sent to the sidecar.
 */
export function sanitizeAwgSyncRequest(input: IAwgSidecarConfig): IAwgSidecarConfig {
    const instance = input.instance
        ? {
              listenPort: input.instance.listenPort,
              listen: input.instance.listen,
              privateKey: input.instance.privateKey,
              publicKey: input.instance.publicKey,
              subnet: input.instance.subnet,
              mtu: input.instance.mtu,
              dns: input.instance.dns,
              keepalive: input.instance.keepalive,
              allowedIps: input.instance.allowedIps,
              endpoint: input.instance.endpoint,
              version: input.instance.version,
              obfuscation: { ...input.instance.obfuscation },
          }
        : null;

    return {
        enabled: input.enabled,
        instance,
        peers: (input.peers ?? []).map((peer) => ({
            publicKey: peer.publicKey,
            presharedKey: peer.presharedKey,
            address: peer.address,
            enabled: peer.enabled,
        })),
        configDir: input.configDir,
    };
}
