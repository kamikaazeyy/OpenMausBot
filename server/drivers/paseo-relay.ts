// OpenMausBot ("Bats") -> Paseo Relay bridge driver.
//
// Routes OMB agent turns through the locally-run Paseo Relay daemon
// (ws://127.0.0.1:6767/ws, bearer password auth) so that:
//   * the official Paseo iOS app and OpenMausBot share the same model list
//     and routing (no mobile frontend changes), and
//   * a Devin CLI quota exhaustion (JSON-RPC code -32011 /
//     resource_exhausted / "cognition.ai/retryable") is automatically
//     rerouted to OpenCode CLI (default: DeepSeek V4.1 Flash).
//
// Provider config shape (stored in OMB instance config):
//   {
//     relayUrl?: string,        // default "ws://127.0.0.1:6767/ws"
//     password?: string,        // Paseo daemon password
//     provider?: string,        // primary Paseo provider, default "devin"
//     fallbackProvider?: string,// fallback Paseo provider, default "opencode"
//     fallbackModel?: string,   // fallback model id, default "deepseek-v4-1-flash"
//     cwd?: string,             // workspace directory for Paseo agents
//     model?: string,           // preferred model passed to Paseo
//   }
//
// NOTE: The Paseo daemon must already have the `opencode` provider registered
// with an absolute command path (e.g. via `set_daemon_config_request` or a
// root edit of /root/.paseo) and OpenCode auth configured for the daemon user.
// This driver surfaces a clear setup error until that is done.

import net from "node:net";
import crypto from "node:crypto";

import type {
  DriverKind,
  InstanceId,
  ModelCatalog,
  ProviderAdapter,
  ProviderInstance,
  ProviderDriver,
  RuntimeEvent,
  RuntimeEventBase,
  RuntimeEventListener,
  SendTurnInput,
  ThreadId,
  TurnId,
  TurnStartResult,
} from "../contracts.ts";
import { newEventId, newId } from "../contracts.ts";

const DRIVER_KIND = "paseo-relay" as DriverKind;
const DEFAULT_RELAY_URL = "ws://127.0.0.1:6767/ws";
const DEFAULT_PROVIDER = "devin";
const DEFAULT_FALLBACK_PROVIDER = "opencode";
const DEFAULT_FALLBACK_MODEL = "deepseek-v4-1-flash";
const WS_PROTOCOL_VERSION = 1;

const TURN_TIMEOUT_MS = 600_000;
const HELLO_TIMEOUT_MS = 10_000;
// How long a request waits for the socket to come back before surfacing an
// error — long enough to ride out a daemon restart, short enough to never
// wedge a turn the way a silent dead-socket write did.
const REQUEST_CONNECT_TIMEOUT_MS = 30_000;

// ── minimal raw WebSocket client (no npm deps) ────────────────────────────

function b64(buf: Uint8Array): string {
    return Buffer.from(buf).toString("base64");
}
function randBytes(n: number): Buffer {
    return crypto.randomBytes(n);
}

const OP_TEXT = 0x1;
const OP_PING = 0x9;
const OP_PONG = 0xA;
const OP_CLOSE = 0x8;

class PaseoSocket {
    private sock: net.Socket | null = null;
    private buf = Buffer.alloc(0);
    private connected = false;
    private handlers = new Map<string, (msg: unknown) => void>();
    private onRawFrame?: (str: string) => void;
    private readonly host: string;
    private readonly port: number;
    private readonly password: string;
    private closedByUser = false;
    private reconnecting = false;
    private reconnectAttempts = 0;
    private reconnectTimer: NodeJS.Timeout | null = null;
    private reconnectAbort: (() => void) | null = null;
    private readonly maxReconnectAttempts = 10;
    private readonly reconnectBaseDelayMs = 2000;
    private readonly maxReconnectDelayMs = 30000;
    private connectWaiters: Array<{ resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout }> = [];

    constructor(host: string, port: number, password: string) {
        this.host = host;
        this.port = port;
        this.password = password;
    }

    isConnected() {
        return this.connected;
    }

    async connect(): Promise<void> {
        const key = b64(randBytes(16));
        const wsProtocol = `paseo.bearer.${this.password}`;
        const req = [
            "GET /ws HTTP/1.1",
            `Host: ${this.host}:${this.port}`,
            "Upgrade: websocket",
            "Connection: Upgrade",
            `Sec-WebSocket-Key: ${key}`,
            "Sec-WebSocket-Version: 13",
            `Sec-WebSocket-Protocol: ${wsProtocol}`,
            `Origin: http://${this.host}:${this.port}`,
            "",
            "",
        ].join("\r\n");

        this.buf = Buffer.alloc(0);
        await new Promise<void>((resolve, reject) => {
            const sock = net.createConnection({ host: this.host, port: this.port });
            sock.setNoDelay(true);
            sock.setTimeout(0);
            let settled = false;
            const settle = (err?: Error) => {
                if (settled) return;
                settled = true;
                if (err) reject(err); else resolve();
            };
            sock.on("connect", () => sock.write(req));
            sock.on("data", (chunk: Buffer) => {
                if (this.sock !== sock) return;
                this.buf = Buffer.concat([this.buf, chunk]);
                if (!this.connected) {
                    const idx = this.buf.indexOf("\r\n\r\n");
                    if (idx === -1) return;
                    const head = this.buf.slice(0, idx).toString("latin1");
                    const statusLine = head.split("\r\n")[0] ?? "";
                    const m = statusLine.match(/HTTP\/1\.1 (\d{3})/);
                    const code = m ? parseInt(m[1], 10) : 0;
                    if (code !== 101) {
                        this.buf = Buffer.alloc(0);
                        settle(new Error(`Paseo WS handshake failed: ${head.slice(0, 200)}`));
                        return;
                    }
                    this.buf = this.buf.slice(idx + 4);
                    this.connected = true;
                    settle();
                }
                this.processFrames();
            });
            sock.on("error", (err) => {
                if (this.sock !== sock) return;
                if (!this.connected) { settle(err); } else { this.emit("error", err); }
            });
            sock.on("close", () => {
                if (this.sock !== sock) return;
                const wasConnected = this.connected;
                this.connected = false;
                if (!settled) settle(new Error("Paseo socket closed during handshake"));
                this.emit("close", undefined);
                if (wasConnected && !this.closedByUser) void this.reconnect();
            });
            sock.on("end", () => { sock.destroy(); });
            this.sock = sock;
        });
    }

    async reconnect(): Promise<void> {
        if (this.closedByUser || this.connected || this.reconnecting) return;
        this.reconnecting = true;
        try {
            while (!this.connected && !this.closedByUser && this.reconnectAttempts < this.maxReconnectAttempts) {
                this.reconnectAttempts += 1;
                try {
                    this.sock?.destroy();
                    await this.connect();
                    // A close that raced the handshake leaves connected=false
                    // even though connect() resolved — count it as a miss.
                    if (!this.connected) throw new Error("Paseo socket dropped during handshake");
                } catch (err) {
                    const delay = Math.min(
                        this.reconnectBaseDelayMs * 2 ** (this.reconnectAttempts - 1),
                        this.maxReconnectDelayMs,
                    );
                    console.error(`[paseo-relay] reconnect attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts} failed: ${err instanceof Error ? err.message : err}; retrying in ${delay}ms`);
                    await new Promise<void>((r) => {
                        this.reconnectAbort = r;
                        this.reconnectTimer = setTimeout(r, delay);
                    });
                    this.reconnectTimer = null;
                    this.reconnectAbort = null;
                }
            }
        } finally {
            this.reconnecting = false;
        }
        if (this.connected) {
            this.reconnectAttempts = 0;
            this.flushConnectWaiters();
            this.emit("reconnected");
        } else if (!this.closedByUser) {
            const err = new Error(`Paseo daemon unreachable after ${this.maxReconnectAttempts} reconnect attempts`);
            console.error(`[paseo-relay] ${err.message}`);
            this.flushConnectWaiters(err);
            this.emit("reconnect_failed", err);
        }
    }

    forceReconnect() {
        this.sock?.destroy();
    }

    whenConnected(timeoutMs: number): Promise<void> {
        if (this.connected) return Promise.resolve();
        if (this.closedByUser) return Promise.reject(new Error("Paseo socket closed"));
        // Demand-driven recovery: a request arriving after the backoff cycle
        // gave up starts a fresh cycle instead of staying dead forever.
        if (!this.reconnecting) { this.reconnectAttempts = 0; void this.reconnect(); }
        return new Promise<void>((resolve, reject) => {
            const waiter = { resolve, reject, timer: setTimeout(() => {
                this.connectWaiters = this.connectWaiters.filter((w) => w !== waiter);
                reject(new Error("Paseo daemon unreachable (still reconnecting)"));
            }, timeoutMs) };
            this.connectWaiters.push(waiter);
        });
    }

    private flushConnectWaiters(err?: Error) {
        const waiters = this.connectWaiters;
        this.connectWaiters = [];
        for (const w of waiters) {
            clearTimeout(w.timer);
            if (err) w.reject(err); else w.resolve();
        }
    }

    on(event: "message" | "close" | "error" | "reconnected" | "reconnect_failed", handler: (msg?: unknown) => void) {
        this.handlers.set(event, handler as (msg: unknown) => void);
    }

    private emit(event: string, msg?: unknown) {
        this.handlers.get(event)?.(msg);
    }

    private sendRaw(opcode: number, payload: Buffer | string): boolean {
        if (!this.sock || this.sock.destroyed || !this.connected) {
            // Never drop a write silently: a dead socket means the daemon went
            // away — kick reconnect so the next request finds a live socket.
            if (!this.closedByUser) void this.reconnect();
            return false;
        }
        const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
        const header = [0x80 | opcode];
        const len = p.length;
        if (len < 126) header.push(0x80 | len);
        else if (len <= 0xffff) { header.push(0x80 | 126, (len >> 8) & 0xff, len & 0xff); }
        else {
            header.push(0x80 | 127);
            const hb = Buffer.alloc(8); hb.writeBigUInt64BE(BigInt(len));
            header.push(...hb);
        }
        const mask = randBytes(4);
        header.push(...mask);
        const masked = Buffer.alloc(p.length);
        for (let i = 0; i < p.length; i++) masked[i] = p[i] ^ mask[i % 4];
        this.sock.write(Buffer.concat([Buffer.from(header), masked]));
        return true;
    }

    sendText(text: string): boolean {
        return this.sendRaw(OP_TEXT, text);
    }

    close() {
        this.closedByUser = true;
        this.reconnectAbort?.();
        if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
        try { this.sendRaw(OP_CLOSE, Buffer.from([0, 0])); } catch {}
        this.sock?.destroy();
        this.flushConnectWaiters(new Error("Paseo socket closed"));
    }

    private processFrames() {
        let frame;
        while ((frame = this.parseFrame())) this.handleFrame(frame);
    }

    private parseFrame() {
        if (this.buf.length < 2) return null;
        const b0 = this.buf[0], b1 = this.buf[1];
        const opcode = b0 & 0x0f;
        const masked = !!(b1 & 0x80);
        let len = b1 & 0x7f, off = 2;
        if (len === 126) {
            if (this.buf.length < 4) return null;
            len = (this.buf[2] << 8) | this.buf[3]; off = 4;
        } else if (len === 127) {
            if (this.buf.length < 10) return null;
            len = this.buf.readUInt32BE(4); off = 10;
        }
        let mask: Buffer | null = null;
        if (masked) {
            if (this.buf.length < off + 4) return null;
            mask = this.buf.slice(off, off + 4); off += 4;
        }
        if (this.buf.length < off + len) return null;
        let payload = this.buf.slice(off, off + len);
        if (masked && mask) { payload = Buffer.alloc(len); for (let i = 0; i < len; i++) payload[i] = this.buf[off + i] ^ mask[i % 4]; }
        this.buf = this.buf.slice(off + len);
        return { opcode, payload };
    }

    private handleFrame({ opcode, payload }: { opcode: number; payload: Buffer }) {
        if (opcode === OP_TEXT) {
            const str = payload.toString("utf8");
            this.onRawFrame?.(str);
            let msg: unknown;
            try { msg = JSON.parse(str); } catch { return; }
            if (msg && typeof msg === "object" && (msg as any).type === "session") {
                this.emit("message", msg);
            }
        } else if (opcode === OP_PING) {
            this.sendRaw(OP_PONG, payload);
        } else if (opcode === OP_CLOSE) {
            this.sock?.destroy();
        }
    }
}

// ── Paseo session client ──────────────────────────────────────────────────

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; timer?: NodeJS.Timeout };

class PaseoSession {
    private socket: PaseoSocket;
    private pending = new Map<string, Pending>();
    private agentHandlers = new Map<string, Array<(evt: unknown) => void>>();
    private helloDone = false;
    private helloInflight: Promise<unknown> | null = null;
    private serverInfo: unknown = null;
    private messageCb: ((msg: unknown) => void) | null = null;
    private reconnectCb: (() => void) | null = null;

    constructor(socket: PaseoSocket) {
        this.socket = socket;
        socket.on("message", (msg) => this.handleMessage(msg));
        socket.on("close", () => {
            this.helloDone = false;
            this.failAll(new Error("Paseo socket closed"));
        });
        socket.on("error", (err) => this.failAll(err as Error));
        socket.on("reconnect_failed", (err) => this.failAll(err as Error));
        socket.on("reconnected", () => { void this.onReconnected(); });
    }

    onMessage(cb: (msg: unknown) => void) {
        this.messageCb = cb;
    }

    onReconnect(cb: () => void) {
        this.reconnectCb = cb;
    }

    // The daemon tears down its per-client session on restart; after the
    // socket comes back we must re-hello before any request is accepted.
    private async onReconnected() {
        try {
            await this.ensureHello();
        } catch {
            // Hello failed on a live socket — drop it so the close handler
            // starts a fresh reconnect cycle.
            this.socket.forceReconnect();
            return;
        }
        this.reconnectCb?.();
    }

    private ensureHello(): Promise<unknown> {
        if (this.helloDone) return Promise.resolve(this.serverInfo);
        if (!this.helloInflight) {
            this.helloInflight = this.connectAndHello("omb-bats", "cli").finally(() => { this.helloInflight = null; });
        }
        return this.helloInflight;
    }

    private nextId() {
        return `omb_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    }

    private waitFor<T>(requestId: string, timeoutMs: number): Promise<T> {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(requestId);
                reject(new Error(`Paseo request timed out: ${requestId}`));
            }, timeoutMs);
            this.pending.set(requestId, { resolve: resolve as (v: unknown) => void, reject, timer });
        });
    }

    private sendEnvelope(message: unknown): boolean {
        return this.socket.sendText(JSON.stringify({ type: "session", message }));
    }

    private handleMessage(envelope: unknown) {
        const e = envelope as any;
        const m = e.message;
        if (!m || typeof m !== "object") return;
        this.messageCb?.(envelope);

        // server_info after hello
        if (m.type === "status" && m.payload && m.payload.status === "server_info") {
            this.serverInfo = m.payload;
            this.helloDone = true;
            return;
        }
        // daemon_config_changed broadcast
        if (m.type === "status" && m.payload && m.payload.status === "daemon_config_changed") {
            this.messageCb?.(envelope);
            return;
        }
        // RPC / status responses correlated by requestId
        if (
            m.type === "rpc_error" ||
            m.type.endsWith("_response") ||
            m.type.endsWith(".response") ||
            m.type.endsWith("/response") ||
            (m.type === "status" && m.payload && m.payload.requestId)
        ) {
            const payload = m.payload ?? {};
            const requestId = payload.requestId;
            const pend = requestId && this.pending.get(requestId);
            if (pend) {
                this.pending.delete(requestId);
                clearTimeout(pend.timer);
                const failure =
                    m.type === "rpc_error" ||
                    payload.status === "agent_create_failed" ||
                    (payload.error && !payload.ok && !payload.status);
                if (failure) pend.reject(new Error(`Paseo ${m.type}: ${payload.error ?? JSON.stringify(payload)}`));
                else pend.resolve(payload);
            }
            return;
        }
        // Agent stream / lifecycle events routed by agentId (top-level or nested)
        const agentId = m.agentId ?? (m.payload && m.payload.agentId);
        if (agentId) {
            const handlers = this.agentHandlers.get(agentId);
            if (handlers) {
                for (const h of handlers) h(m);
            }
            return;
        }
    }

    async connectAndHello(clientId = "omb-bats", clientType = "cli") {
        if (!this.socket.isConnected()) await this.socket.connect();
        this.helloDone = false;
        this.socket.sendText(JSON.stringify({
            type: "hello",
            clientId,
            clientType,
            protocolVersion: WS_PROTOCOL_VERSION,
            capabilities: { allProviders: true, providerSubagents: true },
        }));
        const t0 = Date.now();
        while (!this.helloDone && Date.now() - t0 < HELLO_TIMEOUT_MS) {
            if (!this.socket.isConnected()) throw new Error("Paseo socket dropped during hello");
            await new Promise((r) => setTimeout(r, 20));
        }
        if (!this.helloDone) throw new Error("Paseo hello did not complete (no server_info)");
        return this.serverInfo;
    }

    async request(message: unknown, timeoutMs = TURN_TIMEOUT_MS) {
        // Wait for the socket (and re-hello) instead of writing into a dead
        // socket: after a daemon restart the first request drives recovery.
        await this.socket.whenConnected(Math.min(REQUEST_CONNECT_TIMEOUT_MS, timeoutMs));
        await this.ensureHello();
        const requestId = this.nextId();
        (message as any).requestId = requestId;
        const pending = this.waitFor(requestId, timeoutMs);
        if (!this.sendEnvelope(message)) {
            const pend = this.pending.get(requestId);
            if (pend) {
                this.pending.delete(requestId);
                if (pend.timer) clearTimeout(pend.timer);
                pend.reject(new Error("Paseo socket not connected"));
            }
        }
        return pending;
    }

    async getDaemonConfig() {
        return this.request({ type: "get_daemon_config_request" });
    }

    close() {
        this.socket.close();
    }

    async setDaemonConfig(patch: unknown) {
        return this.request({ type: "set_daemon_config_request", config: patch });
    }

    async createAgent({ provider, cwd, initialPrompt, model, mode }: {
        provider: string; cwd: string; initialPrompt: string; model?: string; mode?: string;
    }) {
        // The daemon reads model selection from config.model (a bare model id);
        // strip a leading "<provider>/" if a full catalog id was configured.
        const bareModel = model?.includes("/") ? model.slice(model.indexOf("/") + 1) : model;
        const message: any = {
            type: "create_agent_request",
            config: {
                provider,
                cwd,
                ...(bareModel ? { model: bareModel } : {}),
                ...(mode ? { modeId: mode } : {}),
            },
            ...(initialPrompt ? { initialPrompt } : {}),
        };
        return this.request(message);
    }

    async sendAgentMessage(agentId: string, text: string) {
        return this.request({ type: "send_agent_message_request", agentId, text });
    }

    async cancelAgent(agentId: string) {
        return this.request({ type: "cancel_agent_request", agentId });
    }

    async respondToPermission(agentId: string, requestId: string, response: { behavior: "allow" | "deny" }) {
        this.sendEnvelope({ type: "agent_permission_response", agentId, requestId, response });
    }

    subscribeAgent(agentId: string, handler: (evt: unknown) => void) {
        const arr = this.agentHandlers.get(agentId) ?? [];
        arr.push(handler);
        this.agentHandlers.set(agentId, arr);
        return () => {
            const arr2 = this.agentHandlers.get(agentId);
            if (arr2) { const i = arr2.indexOf(handler); if (i >= 0) arr2.splice(i, 1); }
        };
    }

    private failAll(err: Error) {
        for (const [, p] of this.pending) { clearTimeout(p.timer); p.reject(err); }
        this.pending.clear();
    }
}

// ── error classification for -32011 quota fallback ────────────────────────

function isQuotaExhausted(err: unknown): boolean {
    const msg = err instanceof Error ? err.message : String(err);
    const low = msg.toLowerCase();
    return (
        low.includes("-32011") ||
        low.includes("resource_exhausted") ||
        low.includes("cognition.ai/retryable") ||
        low.includes("quota") ||
        low.includes("rate limit") ||
        low.includes("rate-limit")
    );
}

function unwrapPaseoEvent(evt: unknown): any {
    const e = evt as any;
    // The daemon wraps provider events in {type:"agent_stream", payload:{event:{...}}}.
    if (e?.type === "agent_stream" && e?.payload?.event) return e.payload.event;
    return e;
}

function extractPaseoErrorText(evt: unknown): string {
    const e = evt as any;
    const candidates = [
        e?.error?.message, e?.payload?.error?.message, e?.error, e?.message,
        e?.payload?.message, e?.item?.error,
    ];
    for (const c of candidates) if (typeof c === "string" && c) return c;
    return JSON.stringify(evt).slice(0, 2000);
}

/** Canceled/interrupted turns must not fail over: re-running the same prompt
 * on a different provider would answer a prompt the user already aborted. */
function isCanceledError(err: unknown): boolean {
    const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
    return msg.includes("cancel") || msg.includes("interrupt") || msg.includes("abort");
}

/** One-line display preview for a tool call (bounded, never raw arguments). */
function toolInputPreview(item: any): string | undefined {
    const d = item?.detail;
    if (!d || typeof d !== "object") return undefined;
    const text = d.command ?? d.filePath ?? d.path ?? d.query ?? d.url ?? d.label;
    return typeof text === "string" && text ? text.slice(0, 200) : undefined;
}

/** Bounded tool result preview for the completed item. */
function toolOutputPreview(item: any): string | undefined {
    const d = item?.detail;
    if (!d || typeof d !== "object") return undefined;
    const text = d.log ?? d.output ?? d.content ?? d.text ?? d.stdout;
    if (typeof text === "string" && text) return text.slice(0, 4000);
    try { return JSON.stringify(d).slice(0, 4000); } catch { return undefined; }
}

// ── OMB ProviderDriver ────────────────────────────────────────────────────

export interface PaseoRelayConfig {
    relayUrl?: string;
    password?: string;
    provider?: string;
    fallbackProvider?: string;
    fallbackModel?: string;
    cwd?: string;
    model?: string;
    /** Auto-answer the provider's permission requests so unattended turns
     * don't stall until the turn timeout. */
    autoApprove?: boolean;
}

interface PaseoRelayStreamState {
    /** messageId of the in-flight assistant message (deltas group by it). */
    assistantMessageId: string | null;
    /** Buffered assistant text; flushed as one item.completed. */
    assistantText: string;
    /** Tool callIds already announced via item.started. */
    toolsStarted: Set<string>;
    /** Dedupes thread_started -> session.started. */
    sessionId: string | null;
}

interface PaseoRelayState {
    session: PaseoSession;
    agentId?: string;
    /** The agentId the stream subscription is bound to. */
    subscribedAgentId?: string;
    /** Unsubscribes the stream handler when the agent is replaced. */
    streamUnsub?: () => void;
    turnListeners: Set<RuntimeEventListener>;
    autoApprove?: boolean;
    /** The turn currently allowed to emit events; null between turns so
     * late packets from a finished/stale agent are dropped. */
    active: {
        threadId: ThreadId;
        turnId: TurnId;
        emit: (event: EmitInput) => void;
        stream: PaseoRelayStreamState;
    } | null;
    /** Usage captured from the terminal turn event for turn.completed. */
    lastTerminalUsage?: { input: number; output: number; cachedInput?: number } | null;
}

function parseRelayUrl(url: string): { host: string; port: number } {
    try {
        const u = new URL(url);
        return { host: u.hostname, port: Number(u.port) || (u.protocol === "wss:" ? 443 : 80) };
    } catch {
        return { host: "127.0.0.1", port: 6767 };
    }
}

const EMPTY_CATALOG: ModelCatalog = { default: "", options: [] };

/** Distributive Omit: plain Omit collapses the RuntimeEvent union to shared
 * keys and rejects variant fields (ok, itemType, streamKind, ...). */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
type EmitInput = DistributiveOmit<RuntimeEvent, "eventId" | "provider" | "providerInstanceId" | "threadId" | "createdAt">;

class PaseoRelayDriverImpl implements ProviderDriver<PaseoRelayConfig> {
    readonly driverKind = DRIVER_KIND;
    readonly metadata = {
        displayName: "Paseo Relay (Devin + OpenCode fallback)",
        supportsMultipleInstances: true,
        access: "custom" as const,
    };

    private sessions = new Map<string, PaseoRelayState>();

    decodeConfig(raw: unknown): PaseoRelayConfig {
        if (!raw || typeof raw !== "object") return this.defaultConfig();
        const c = raw as Partial<PaseoRelayConfig>;
        const d = this.defaultConfig();
        return {
            relayUrl: c.relayUrl ?? d.relayUrl,
            password: c.password ?? d.password,
            provider: c.provider ?? DEFAULT_PROVIDER,
            fallbackProvider: c.fallbackProvider ?? DEFAULT_FALLBACK_PROVIDER,
            fallbackModel: c.fallbackModel ?? DEFAULT_FALLBACK_MODEL,
            cwd: c.cwd ?? d.cwd,
            model: c.model ?? d.model,
            autoApprove: c.autoApprove ?? d.autoApprove,
        };
    }
    defaultConfig(): PaseoRelayConfig {
        return {
            relayUrl: DEFAULT_RELAY_URL,
            password: "",
            provider: DEFAULT_PROVIDER,
            fallbackProvider: DEFAULT_FALLBACK_PROVIDER,
            fallbackModel: DEFAULT_FALLBACK_MODEL,
            cwd: undefined,
            model: undefined,
            autoApprove: false,
        };
    }
    get models(): ModelCatalog {
        return EMPTY_CATALOG; // Paseo Relay reports its own model list; OMB picker reflects the relay.
    }

    async create(input: { instanceId: InstanceId; displayName: string | undefined; environment: Record<string, string>; enabled: boolean; config: PaseoRelayConfig }): Promise<ProviderInstance> {
        const config = this.decodeConfig(input.config);
        const { host, port } = parseRelayUrl(config.relayUrl ?? DEFAULT_RELAY_URL);
        if (!config.password) {
            throw new Error("Paseo Relay password is required (set config.password or PASEO_PASSWORD env).");
        }

        const socket = new PaseoSocket(host, port, config.password);
        const session = new PaseoSession(socket);
        await session.connectAndHello("omb-bats", "cli");

        const instanceId = input.instanceId;
        const state: PaseoRelayState = {
            session,
            agentId: undefined,
            subscribedAgentId: undefined,
            streamUnsub: undefined,
            turnListeners: new Set<RuntimeEventListener>(),
            autoApprove: config.autoApprove ?? false,
            active: null,
            lastTerminalUsage: null,
        };
        this.sessions.set(instanceId, state);

        // A daemon restart drops the server-side agent stream keyed by the
        // old agentId. Warn listeners and forget it so the next turn creates
        // a fresh agent instead of writing to a dead stream.
        session.onReconnect(() => {
            if (!state.agentId) return;
            const lost = state.agentId;
            state.agentId = undefined;
            state.subscribedAgentId = undefined;
            state.streamUnsub?.();
            state.streamUnsub = undefined;
            for (const l of state.turnListeners) {
                l({
                    eventId: newEventId(),
                    provider: DRIVER_KIND,
                    providerInstanceId: instanceId,
                    threadId: "system",
                    createdAt: new Date().toISOString(),
                    type: "runtime.error",
                    message: `Paseo Relay reconnected after a daemon restart; agent ${lost} was reset — the next turn starts a fresh agent.`,
                });
            }
        });

        // Forward daemon-level config-changed broadcasts (e.g. provider registration) to listeners.
        session.onMessage((env: unknown) => {
            const e = env as any;
            const m = e?.message;
            if (m?.type === "status" && m?.payload?.status === "daemon_config_changed") {
                const cfg = m.payload.config ?? {};
                const providers = cfg.providers ?? {};
                const opencode = providers.opencode;
                const opencodeReady = opencode && opencode.enabled && Boolean(opencode.command);
                for (const l of state.turnListeners) {
                    l({
                        eventId: newEventId(),
                        provider: DRIVER_KIND,
                        providerInstanceId: instanceId,
                        threadId: "system",
                        createdAt: new Date().toISOString(),
                        type: "runtime.error",
                        message: opencodeReady
                            ? "Paseo Relay: OpenCode provider registered (command set). Ready for -32011 fallback."
                            : "Paseo Relay: OpenCode provider not yet registered; -32011 fallback unavailable until root configures opencode.",
                        setup: !opencodeReady,
                    });
                }
            }
        });

        const adapter: ProviderAdapter = {
            provider: DRIVER_KIND,
            capabilities: {
                sessionModelSwitch: "in-session",
                images: false,
                nativeImageInput: false,
                effortLevels: [],
                modelVariants: false,
                queueing: false,
                localComputerMcp: false,
                customMcp: false,
                composioMcp: false,
                browserMcp: false,
                phoneMcp: false,
                agentsMcp: false,
            },
            sendTurn: async (turn: SendTurnInput): Promise<TurnStartResult> => {
                const turnId = newId() as TurnId;
                const threadId = turn.threadId;
                const text = turn.text;
                const cwd = turn.cwd ?? config.cwd;
                const model = turn.model ?? config.model;
                const emit = (event: EmitInput) => {
                    const base: RuntimeEventBase = {
                        eventId: newEventId(),
                        provider: DRIVER_KIND,
                        providerInstanceId: instanceId,
                        threadId,
                        createdAt: new Date().toISOString(),
                        turnId,
                    };
                    const ev = { ...base, ...event } as RuntimeEvent;
                    for (const l of state.turnListeners) l(ev);
                };

                const finish = (ok: boolean, stopReason?: string, usage?: { input: number; output: number; cachedInput?: number }) => {
                    emit({ type: "turn.completed", ok, stopReason, ...(usage ? { usage } : {}) });
                };

                // All stream events route through this per-turn context: the
                // daemon-side agent outlives a single turn, so its (persistent)
                // subscription must emit under the CURRENT turn, not the one
                // that happened to create the agent.
                state.active = {
                    threadId,
                    turnId,
                    emit,
                    stream: { assistantMessageId: null, assistantText: "", toolsStarted: new Set(), sessionId: null },
                };
                state.lastTerminalUsage = null;

                emit({ type: "turn.started" });

                try {
                    // Reuse an existing Paseo agent for this thread, else create one.
                    // A newly created agent starts its turn from initialPrompt, so
                    // only send a follow-up message when reusing an existing agent.
                    let promptDelivered = false;
                    if (!state.agentId) {
                        const created = await session.createAgent({
                            provider: config.provider ?? DEFAULT_PROVIDER,
                            cwd: cwd ?? process.cwd(),
                            initialPrompt: text,
                            ...(model ? { model } : {}),
                        });
                        const agent = (created as any)?.agent ?? (created as any);
                        state.agentId = agent?.id ?? (created as any)?.agentId;
                        if (!state.agentId) throw new Error(`Paseo create_agent returned no agentId: ${JSON.stringify(created).slice(0, 300)}`);
                        this.ensureStreamSubscription(state, instanceId);
                        promptDelivered = true;
                    }

                    try {
                        if (!promptDelivered) await session.sendAgentMessage(state.agentId!, text);
                        // Stream events arrive via the agent subscription above.
                        await this.waitForTurnCompletion(state);
                    } catch (err) {
                        // Primary provider failed -> fallback to OpenCode — unless
                        // the turn was deliberately canceled/interrupted: re-running
                        // a dead prompt on a different model spawns a stray reply.
                        if (!isCanceledError(err) && config.fallbackProvider && config.fallbackProvider !== config.provider) {
                            emit({
                                type: "turn.retrying",
                                attempt: 1,
                                delayMs: 0,
                                reason: isQuotaExhausted(err)
                                    ? `Primary provider "${config.provider}" quota exhausted; failing over to "${config.fallbackProvider}"`
                                    : `Primary provider "${config.provider}" failed (${err instanceof Error ? err.message : String(err)}); failing over to "${config.fallbackProvider}"`,
                            });
                            // Cancel the stale agent so a still-running primary turn
                            // can't keep streaming (or burning quota) in the background.
                            try { if (state.agentId) await session.cancelAgent(state.agentId); } catch {}
                            state.agentId = undefined;
                            const modelUsed = config.fallbackModel ?? model;
                            const created = await session.createAgent({
                                provider: config.fallbackProvider,
                                cwd: cwd ?? process.cwd(),
                                initialPrompt: text,
                                ...(modelUsed ? { model: modelUsed } : {}),
                            });
                            const agent = (created as any)?.agent ?? (created as any);
                            state.agentId = agent?.id ?? (created as any)?.agentId;
                            if (!state.agentId) throw new Error(`Paseo fallback create_agent returned no agentId`);
                            this.ensureStreamSubscription(state, instanceId);
                            await this.waitForTurnCompletion(state);
                        } else {
                            throw err;
                        }
                    }

                    finish(true, undefined, state.lastTerminalUsage ?? { input: 0, output: 0 });
                    return { turnId };
                } catch (err) {
                    const message = err instanceof Error ? err.message : String(err);
                    emit({ type: "runtime.error", message, terminal: true });
                    finish(false, message);
                    return { turnId };
                } finally {
                    if (state.active?.turnId === turnId) state.active = null;
                }
            },
            interruptTurn: async (_threadId: ThreadId) => {
                const st = this.sessions.get(instanceId);
                if (st?.agentId) {
                    try { await st.session.cancelAgent(st.agentId); } catch {}
                }
            },
            respondToRequest: async () => "unavailable",
            hasSession: (_threadId: ThreadId) => Boolean(state.agentId),
            stopAll: async () => {
                try { if (state.agentId) await session.cancelAgent(state.agentId); } catch {}
            },
            onEvent: (listener: RuntimeEventListener) => {
                state.turnListeners.add(listener);
                return () => { state.turnListeners.delete(listener); };
            },
        };

        return {
            instanceId,
            driverKind: DRIVER_KIND,
            displayName: input.displayName,
            enabled: input.enabled,
            get models() { return EMPTY_CATALOG; },
            snapshot: async () => {
                try {
                    await session.getDaemonConfig();
                    return { state: "available" as const, authenticated: true, version: "0.8.0" };
                } catch (err) {
                    return { state: "unavailable" as const, reason: err instanceof Error ? err.message : String(err) };
                }
            },
            adapter,
            dispose: async () => {
                try { if (state.agentId) await session.cancelAgent(state.agentId); } catch {}
                try { session.close(); } catch {}
                this.sessions.delete(instanceId);
            },
        };
    }

    /** Bind the stream handler to the current agent once; the handler reads the
     * per-turn context off `state` so agent reuse across turns/tags stays
     * correctly attributed instead of closing over a stale emit. */
    private ensureStreamSubscription(state: PaseoRelayState, _instanceId: InstanceId) {
        if (!state.agentId || state.subscribedAgentId === state.agentId) return;
        state.streamUnsub?.();
        const ownerAgentId = state.agentId;
        state.streamUnsub = state.session.subscribeAgent(ownerAgentId, (evt) =>
            this.relayPaseoEvent(evt, state, ownerAgentId),
        );
        state.subscribedAgentId = ownerAgentId;
    }

    private relayPaseoEvent(
        evt: unknown,
        state: PaseoRelayState,
        ownerAgentId: string,
    ) {
        // Drop events from a superseded agent (post-fallback, post-reconnect)
        // and from outside any active turn.
        if (ownerAgentId !== state.agentId) return;
        const active = state.active;
        if (!active) return;
        const emit = active.emit;
        const stream = active.stream;
        const flushAssistantText = () => {
            const text = stream.assistantText;
            stream.assistantText = "";
            stream.assistantMessageId = null;
            if (text.trim()) emit({ type: "item.completed", itemType: "assistant_text", text });
        };

        const e = unwrapPaseoEvent(evt);
        const evType = e?.type;
        const payload = e?.payload ?? e;

        // Terminal turn events are consumed by waitForTurnCompletion; they are
        // NOT forwarded — the driver emits the single turn.completed itself.
        // Buffered assistant text is flushed first so a partial answer isn't
        // lost when the turn ends.
        if (evType === "turn_completed") {
            flushAssistantText();
            const u = payload?.usage;
            state.lastTerminalUsage = u
                ? {
                    input: u.input ?? u.inputTokens ?? 0,
                    output: u.output ?? u.outputTokens ?? 0,
                    ...((u.cachedInput ?? u.cachedInputTokens) ? { cachedInput: u.cachedInput ?? u.cachedInputTokens } : {}),
                }
                : null;
            return;
        }
        if (evType === "turn_failed" || evType === "turn_canceled") {
            flushAssistantText();
            return;
        }
        if (evType === "turn_started") return; // the driver emitted its own turn.started

        if (evType === "thread_started") {
            const sessionId = payload?.sessionId ?? null;
            if (sessionId !== stream.sessionId) {
                stream.sessionId = sessionId;
                emit({ type: "session.started", sessionId, model: payload?.model ?? null });
            }
            return;
        }

        if (evType === "timeline") {
            const item = payload?.item ?? {};
            // The daemon translates each ACP *_chunk update into a timeline item
            // whose `text` is a DELTA; chunks of one message share `messageId`.
            // Buffer them and commit a single assistant_text item per message.
            if (item?.type === "assistant_message" && typeof item.text === "string" && item.text) {
                const messageId = typeof item.messageId === "string" ? item.messageId : null;
                if (stream.assistantMessageId && messageId && stream.assistantMessageId !== messageId) flushAssistantText();
                stream.assistantMessageId = messageId ?? stream.assistantMessageId;
                stream.assistantText += item.text;
                emit({ type: "content.delta", streamKind: "assistant_text", delta: item.text });
                return;
            }
            if (item?.type === "reasoning") {
                if (typeof item.text === "string" && item.text) {
                    emit({ type: "content.delta", streamKind: "reasoning_text", delta: item.text });
                }
                return;
            }
            if (item?.type === "tool_call" || item?.type === "tool") {
                // A tool call interrupts the in-flight text — commit it first.
                flushAssistantText();
                const callId = item.callId ?? item.id;
                if (callId && !stream.toolsStarted.has(callId)) {
                    stream.toolsStarted.add(callId);
                    emit({
                        type: "item.started",
                        itemType: "tool",
                        itemId: callId,
                        title: String(item.metadata?.title ?? item.name ?? item.detail?.label ?? "tool").slice(0, 80),
                        ...(item.detail?.command ? { summary: String(item.detail.command).slice(0, 200) } : {}),
                        input: toolInputPreview(item),
                    });
                }
                if (item.status === "completed" || item.status === "failed") {
                    emit({
                        type: "item.completed",
                        itemType: "tool",
                        itemId: callId,
                        ok: item.status !== "failed",
                        output: toolOutputPreview(item),
                    });
                }
                return;
            }
            // user_message echoes, todo/plan snapshots: not rendered as items.
            return;
        }

        // Auto-approve permission requests so Devin doesn't hang waiting for
        // manual approval. Falls through to OpenCode fallback if Devin then
        // errors out (quota, timeout, etc.).
        if (evType === "agent_permission_request" || evType === "permission_requested") {
            const request = payload?.request ?? {};
            const permissionId = request.id ?? payload?.requestId ?? payload?.id ?? payload?.permissionId;
            const agentId = payload?.agentId ?? e?.agentId ?? state.agentId;
            if (state.autoApprove && agentId && permissionId) {
                void state.session.respondToPermission(agentId, permissionId, { behavior: "allow" });
                emit({ type: "runtime.error", message: "Auto-approved permission request" });
            } else {
                emit({ type: "runtime.error", message: "Permission request requires manual approval; turn stalled" });
            }
            return;
        }

        // Surface provider errors (incl. -32011) so the driver can fallback.
        if (evType === "session.error" || (payload && (payload.error || payload.status === "error"))) {
            const msg = extractPaseoErrorText(evt);
            emit({ type: "runtime.error", message: msg });
            return;
        }
    }

    private async waitForTurnCompletion(state: PaseoRelayState) {
        // Paseo streams terminal turn events via the agent handler. Resolve on
        // turn_completed; reject on turn_failed/turn_canceled so the caller can
        // detect -32011 quota exhaustion and fail over to the fallback provider.
        return new Promise<void>((resolve, reject) => {
            const timer = setTimeout(() => {
                unsubscribe();
                reject(new Error("Paseo turn timed out"));
            }, TURN_TIMEOUT_MS);
            const unsubscribe = state.session.subscribeAgent(state.agentId!, (evt) => {
                const e = unwrapPaseoEvent(evt);
                if (e?.type === "turn_completed") {
                    clearTimeout(timer);
                    unsubscribe();
                    resolve();
                } else if (e?.type === "turn_failed" || e?.type === "turn_canceled") {
                    clearTimeout(timer);
                    unsubscribe();
                    const code = e?.code != null ? `code ${e.code}` : "";
                    const reason = e?.error ?? e?.reason ?? e?.payload?.error ?? e?.type;
                    reject(new Error(`${code} ${reason}`.trim() || String(e?.type)));
                }
            });
        });
    }
}

export const PaseoRelayDriver: ProviderDriver<PaseoRelayConfig> = new PaseoRelayDriverImpl();
