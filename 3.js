import { connect } from 'cloudflare:sockets';

let myID = '4f1b9a56-a2bd-4f6f-9162-9b5506dda207';
let pyIP = 'tp50000.kr.proxyip.fgfw.eu.org';

const RACE_ENABLED = true;
const GEN_RACE_DELAY_MS = 350;
const MAX_EARLY_BUFFER_BYTES = 64 * 1024;

const GENERAL_COALESCE_MS = 0;
const GENERAL_COALESCE_MAX_BYTES = 0;

const SEND_HEADER_EARLY = true;

const preferredDomains = [
    'store.ubi.com', 'ip.sb', 'mfa.gov.ua', 'shopify.com',
    'cloudflare-dl.byoip.top', 'staticdelivery.nexusmods.com',
    'bestcf.top', 'cf.090227.xyz', 'cf.zhetengsha.eu.org',
    'baipiao.cmliussss.abrdns.com', 'saas.sin.fan'
];

let proxyConfig = { host: '', port: null };

function parseProxyIP(input) {
    proxyConfig = { host: '', port: null };
    if (!input) return;
    const parts = input.split(':');
    proxyConfig.host = parts[0].trim();
    if (parts.length > 1) {
        const p = parseInt(parts[1].trim(), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) proxyConfig.port = p;
    }
}

function extractProxyFromPath(pathname) {
    const m = /^\/proxy=([^/]+)(?:\/.*)?$/.exec(pathname);
    return m ? m[1] : null;
}

function getEffectiveProxyIP(url) {
    const fromQuery = (url.searchParams.get('proxy') || '').trim();
    const fromPath = extractProxyFromPath(url.pathname);
    return fromQuery || fromPath || pyIP;
}

function concatArrayBuffers(...arrays) {
    const total = arrays.reduce((sum, a) => sum + a.byteLength, 0);
    const tmp = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        tmp.set(new Uint8Array(a), offset);
        offset += a.byteLength;
    }
    return tmp.buffer;
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { error: null };
    try {
        const b64 = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const dec = atob(b64);
        const u8 = Uint8Array.from(dec, c => c.charCodeAt(0));
        return { earlyData: u8.buffer, error: null };
    } catch (e) {
        return { error: e };
    }
}

const TEXT_DECODER = new TextDecoder();

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) throw TypeError('Invalid UUID');
    return uuid;
}

function getProxyConfig(uuid, currentHost, proxyHostPort) {
    const protocol = atob(atob('ZG14bGMzTT0='));
    const path = `/proxy=${proxyHostPort}`;
    const params = new URLSearchParams({
        encryption: 'none',
        type: 'ws',
        host: currentHost,
        path: path
    });

    return btoa(preferredDomains.map((domain, idx) => {
        const alias = `wk_${String(idx + 1).padStart(2, '0')}`;
        return `${protocol}://${uuid}@${domain}:80?${params.toString()}#${alias}`;
    }).join('\n')).replace(/\+/g, '-').replace(/\//g, '_');
}

if (!isValidUUID(myID)) {
    throw new Error('Invalid UUID');
}

export default {
    async fetch(request) {
        try {
            const url = new URL(request.url);
            const effectiveProxyIP = getEffectiveProxyIP(url);
            parseProxyIP(effectiveProxyIP);
            let pathUUID = null;
            const pm = /^\/proxy=([^/]+)(?:\/([0-9a-f-]{36}))?$/.exec(url.pathname);
            if (pm && pm[2]) {
                pathUUID = pm[2];
            } else if (url.pathname.length > 1) {
                pathUUID = url.pathname.substring(1);
            }

            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (url.pathname === '/') {
                    return new Response('Success', {
                        status: 200,
                        headers: { 'Content-Type': 'text/plain;charset=utf-8' }
                    });
                }
                if (pathUUID && pathUUID === myID) {
                    const cfg = getProxyConfig(pathUUID, request.headers.get('Host'), effectiveProxyIP);
                    return new Response(cfg, {
                        status: 200,
                        headers: { 'Content-Type': 'text/plain;charset=utf-8' }
                    });
                }
                return new Response('Invalid UUID', {
                    status: 400,
                    headers: { 'Content-Type': 'text/plain;charset=utf-8' }
                });
            }

            return await proxyOverWSHandler(request);
        } catch (err) {
            return new Response(err.toString(), {
                status: 500,
                headers: { 'Content-Type': 'text/plain;charset=utf-8' }
            });
        }
    }
};

async function proxyOverWSHandler(request) {
    const url = new URL(request.url);
    const effProxy = getEffectiveProxyIP(url);
    parseProxyIP(effProxy);

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWS = makeReadableWebSocketStream(server, earlyDataHeader);

    const remote = {
        value: null,
        writer: null,
        ready: false,
        started: false,
        earlyBuf: [],
        earlyBytes: 0
    };
    let udpWrite = null;
    let isDns = false;

    server.addEventListener('close', () => { try { remote.value && remote.value.close(); } catch {} });
    server.addEventListener('error', () => { try { remote.value && remote.value.close(); } catch {} });

    readableWS.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDns && udpWrite) {
                udpWrite(chunk);
                return;
            }

            if (remote.ready && remote.writer) {
                await remote.writer.write(chunk);
                return;
            }

            if (!remote.started) {
                const {
                    hasError,
                    message,
                    portRemote = 443,
                    addressRemote = '',
                    rawDataIndex,
                    protoVersion = new Uint8Array([0, 0]),
                    isUDP
                } = processProxyHeader(chunk, myID);
                if (hasError) throw new Error(message);

                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                    } else {
                        throw new Error('UDP only allowed for DNS (port 53)');
                    }
                }

                const proxyRespHeader = new Uint8Array([protoVersion[0], 0]);
                const rawClient = chunk.slice(rawDataIndex);

                if (isDns) {
                    const { write } = await handleUDPOutBound(server, proxyRespHeader);
                    udpWrite = write;
                    udpWrite(rawClient);
                    remote.started = true;
                    return;
                }

                handleTCPOutBoundOptimized(remote, addressRemote, portRemote, rawClient, server, proxyRespHeader);
                remote.started = true;
                return;
            }

            if (remote.earlyBytes + chunk.byteLength <= MAX_EARLY_BUFFER_BYTES) {
                remote.earlyBuf.push(chunk);
                remote.earlyBytes += chunk.byteLength;
            } else if (remote.writer) {
                await remote.writer.write(chunk);
            }
        }
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: client });
}

function makeReadableWebSocketStream(ws, earlyDataHeader) {
    let cancelled = false;
    const { earlyData } = base64ToArrayBuffer(earlyDataHeader);

    return new ReadableStream({
        start(controller) {
            if (earlyData) controller.enqueue(new Uint8Array(earlyData));
            ws.addEventListener('message', e => {
                if (!cancelled) controller.enqueue(e.data);
            });
            ws.addEventListener('close', () => {
                safeCloseWebSocket(ws);
                if (!cancelled) controller.close();
            });
            ws.addEventListener('error', err => controller.error(err));
        },
        cancel() {
            cancelled = true;
            safeCloseWebSocket(ws);
        }
    });
}

function processProxyHeader(buf, myID) {
    try {
        if (buf.byteLength < 24) throw new Error('Invalid data');

        const version = new Uint8Array(buf.slice(0, 1));
        const uuidStr = stringify(new Uint8Array(buf.slice(1, 17))).toLowerCase();
        if (uuidStr !== myID.toLowerCase()) throw new Error('Invalid user');

        const optLen = new Uint8Array(buf.slice(17, 18))[0];
        const cmdIdx = 18 + optLen;
        const cmd = new Uint8Array(buf.slice(cmdIdx, cmdIdx + 1))[0];
        const isUDP = cmd === 2;
        if (cmd !== 1 && !isUDP) throw new Error(`Unsupported command ${cmd}`);

        const portIdx = cmdIdx + 1;
        if (buf.byteLength < portIdx + 2) throw new Error('Missing port');
        const port = new DataView(buf.slice(portIdx, portIdx + 2)).getUint16(0);

        let addrIdx = portIdx + 2;
        if (buf.byteLength < addrIdx + 1) throw new Error('Missing address type');
        const addrType = new Uint8Array(buf.slice(addrIdx, addrIdx + 1))[0];
        addrIdx += 1;

        let addr = '', addrLen = 0;
        switch (addrType) {
            case 1:
                addrLen = 4;
                if (buf.byteLength < addrIdx + addrLen) throw new Error('Incomplete IPv4');
                addr = new Uint8Array(buf.slice(addrIdx, addrIdx + addrLen)).join('.');
                break;
            case 2:
                addrLen = new Uint8Array(buf.slice(addrIdx, addrIdx + 1))[0];
                addrIdx += 1;
                if (buf.byteLength < addrIdx + addrLen) throw new Error('Incomplete domain');
                addr = TEXT_DECODER.decode(buf.slice(addrIdx, addrIdx + addrLen));
                break;
            case 3:
                addrLen = 16;
                if (buf.byteLength < addrIdx + addrLen) throw new Error('Incomplete IPv6');
                const dv = new DataView(buf.slice(addrIdx, addrIdx + addrLen));
                const parts = [];
                for (let i = 0; i < 8; i++) parts.push(dv.getUint16(i * 2).toString(16));
                addr = parts.join(':');
                break;
            default:
                throw new Error(`Invalid address type ${addrType}`);
        }

        const rawIdx = addrIdx + addrLen;
        return {
            hasError: false,
            addressRemote: addr,
            portRemote: port,
            rawDataIndex: rawIdx,
            protoVersion: version,
            isUDP
        };
    } catch (e) {
        return { hasError: true, message: e.message };
    }
}

function createWSSender(ws, proxyHeader, options) {
    const {
        headerAlreadySent = false,
        coalesceMs = 0,
        maxBytes = 0
    } = options || {};

    let headerSent = !!headerAlreadySent;
    let parts = [];
    let bytes = 0;
    let timer = null;
    let closed = false;

    function sendHeaderIfNeeded() {
        if (!headerSent) {
            ws.send(proxyHeader);
            headerSent = true;
        }
    }

    function flush() {
        if (closed) return;
        if (!headerSent) sendHeaderIfNeeded();
        if (bytes === 0) return;

        const buf = new Uint8Array(bytes);
        let off = 0;
        for (const p of parts) {
            const u8 = p instanceof Uint8Array ? p : new Uint8Array(p);
            buf.set(u8, off);
            off += u8.byteLength;
        }
        parts.length = 0;
        bytes = 0;
        ws.send(buf);
    }

    function scheduleFlush() {
        if (timer || coalesceMs <= 0) return;
        timer = setTimeout(() => {
            timer = null;
            flush();
        }, coalesceMs);
    }

    return {
        push(chunk) {
            if (closed) return;
            if (!coalesceMs || !maxBytes) {
                if (!headerSent) sendHeaderIfNeeded();
                ws.send(chunk);
                return;
            }
            const u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
            parts.push(u8);
            bytes += u8.byteLength;
            if (bytes >= maxBytes) {
                flush();
            } else {
                scheduleFlush();
            }
        },
        flush() {
            if (timer) { try { clearTimeout(timer); } catch {} timer = null; }
            flush();
        },
        markHeaderSent() {
            headerSent = true;
        },
        close() {
            if (timer) { try { clearTimeout(timer); } catch {} timer = null; }
            closed = true;
            parts.length = 0;
            bytes = 0;
        }
    };
}

async function handleTCPOutBoundOptimized(remote, address, port, initData, ws, proxyHeader) {
    if (remote._active) return;
    remote._active = true;

    const raceDelay = RACE_ENABLED && proxyConfig.host ? GEN_RACE_DELAY_MS : null;

    let selected = null;
    let directSock = null;
    let proxySock = null;
    let fallbackTimer = null;
    let closed = false;
    let headerSent = false;

    const wsSender = createWSSender(ws, proxyHeader, {
        headerAlreadySent: false,
        coalesceMs: GENERAL_COALESCE_MS,
        maxBytes: GENERAL_COALESCE_MAX_BYTES
    });

    function clearFallbackTimer() {
        if (fallbackTimer) { try { clearTimeout(fallbackTimer); } catch {} fallbackTimer = null; }
    }

    async function becomeWinner(sock, label) {
        selected = label;
        clearFallbackTimer();

        try { if (label === 'direct' && proxySock) proxySock.close(); } catch {}
        try { if (label === 'proxy' && directSock) directSock.close(); } catch {}

        remote.value = sock;
        remote.writer = sock.writable.getWriter();
        if (remote.earlyBuf.length) {
            for (const buf of remote.earlyBuf) {
                await remote.writer.write(buf);
            }
            remote.earlyBuf.length = 0;
            remote.earlyBytes = 0;
        }
        remote.ready = true;
    }

    async function startReader(sock, label) {
        const reader = sock.readable.getReader();
        try {
            let first = true;
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                if (closed) break;

                if (!selected) await becomeWinner(sock, label);

                if (first) {
                    if (SEND_HEADER_EARLY && !headerSent && ws.readyState === 1) {
                        wsSender.push(new Uint8Array(0));
                        headerSent = true;
                    }
                    first = false;
                }

                wsSender.push(value);
            }
        } catch {
        } finally {
            try { reader.releaseLock(); } catch {}
            if (!closed && selected === label) {
                try { wsSender.flush(); } catch {}
                closed = true;
                safeCloseWebSocket(ws);
                wsSender.close();
            }
        }
    }

    directSock = connect({ hostname: address, port });
    try {
        const w = directSock.writable.getWriter();
        await w.write(initData);
        w.releaseLock();
        if (SEND_HEADER_EARLY && !headerSent && ws.readyState === 1) {
            wsSender.push(new Uint8Array(0));
            headerSent = true;
        }
    } catch {}
    startReader(directSock, 'direct');

    if (raceDelay !== null) {
        const spawnProxy = async () => {
            if (selected || closed) return;
            try {
                proxySock = connect({
                    hostname: proxyConfig.host,
                    port: proxyConfig.port !== null ? proxyConfig.port : port
                });
                const w2 = proxySock.writable.getWriter();
                await w2.write(initData);
                w2.releaseLock();
                if (SEND_HEADER_EARLY && !headerSent && ws.readyState === 1) {
                    wsSender.push(new Uint8Array(0));
                    headerSent = true;
                }
                startReader(proxySock, 'proxy');
            } catch {}
        };
        if (raceDelay <= 0) {
            spawnProxy();
        } else {
            fallbackTimer = setTimeout(spawnProxy, raceDelay);
        }
    }
}

async function handleUDPOutBound(ws, proxyHeader) {
    let headerSent = false;

    const transform = new TransformStream({
        transform(chunk, controller) {
            for (let i = 0; i < chunk.byteLength;) {
                const len = new DataView(chunk.buffer, chunk.byteOffset + i, 2).getUint16(0);
                const data = new Uint8Array(chunk.buffer, chunk.byteOffset + i + 2, len);
                controller.enqueue(data);
                i += 2 + len;
            }
        }
    });

    transform.readable.pipeTo(new WritableStream({
        async write(dQuery) {
            const resp = await fetch('https://dns.google/dns-query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/dns-message',
                    'Accept': 'application/dns-message'
                },
                body: dQuery
            });
            const ans = await resp.arrayBuffer();
            const sz = ans.byteLength;
            const szBuf = new Uint8Array([(sz >> 8) & 0xff, sz & 0xff]);

            if (ws.readyState === 1) {
                if (!headerSent) { ws.send(proxyHeader); headerSent = true; }
                ws.send(szBuf);
                ws.send(ans);
            }
        }
    })).catch(() => {});

    const writer = transform.writable.getWriter();
    return {
        write(chunk) {
            writer.write(chunk);
        }
    };
}

function safeCloseWebSocket(sock) {
    try {
        if (sock.readyState === 1 || sock.readyState === 2) {
            sock.close();
        }
    } catch {}
}
