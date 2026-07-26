const http = require('http');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const LISTEN_HOST = '0.0.0.0';
const LISTEN_PORT = 8080;

let yourUUID = '16316c73-4199-4de2-9bfd-b506e5420c8b';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

function base64ToBuffer(b64Str) {
    if (!b64Str) return null;
    try {
        const normalized = b64Str.replace(/-/g, '+').replace(/_/g, '/');
        return Buffer.from(normalized, 'base64');
    } catch (_) {
        return null;
    }
}

function decodeMaybeBase64Credential(username, password) {
    if (password || !username) {
        return { username, password };
    }

    const decoded = base64ToBuffer(username);
    if (!decoded) {
        return { username, password };
    }

    const text = decoded.toString('utf8');
    const separator = text.indexOf(':');
    if (separator === -1) {
        return { username, password };
    }

    return {
        username: text.slice(0, separator),
        password: text.slice(separator + 1),
    };
}

function parseProxyAddress(proxyStr) {
    if (!proxyStr) return null;

    let value = proxyStr.trim();
    if (value.startsWith('/')) {
        value = value.slice(1);
    }

    if (!/^(socks|socks5|http|https):\/\//i.test(value)) {
        return null;
    }

    try {
        const url = new URL(value.replace(/^socks:\/\//i, 'socks5://'));
        const type = url.protocol.slice(0, -1).toLowerCase();
        const isSocks = type === 'socks5';
        const port = Number(url.port) || (type === 'https' ? 443 : isSocks ? 1080 : 80);
        let username = url.username ? decodeURIComponent(url.username) : '';
        let password = url.password ? decodeURIComponent(url.password) : '';

        if (isSocks) {
            ({ username, password } = decodeMaybeBase64Credential(username, password));
        }

        return {
            type,
            host: url.hostname,
            port,
            username,
            password,
        };
    } catch (_) {
        return null;
    }
}

function getProxyFromRequestPath(requestUrl) {
    const rawPath = (requestUrl || '/').split('?')[0];
    let path = rawPath.startsWith('/') ? rawPath.slice(1) : rawPath;

    try {
        path = decodeURIComponent(path);
    } catch (_) {}

    return parseProxyAddress(path);
}

function parseWsPacketHeader(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };

    const version = chunk.subarray(0, 1);
    if (formatIdentifier(chunk.subarray(1, 17)).toLowerCase() !== token.toLowerCase()) {
        return { hasError: true, message: 'Invalid uuid' };
    }

    const optLen = chunk[17];
    const cmd = chunk[18 + optLen];
    let isUDP = false;
    if (cmd === 1) {
        isUDP = false;
    } else if (cmd === 2) {
        isUDP = true;
    } else {
        return { hasError: true, message: 'Invalid cmd' };
    }

    const portIdx = 19 + optLen;
    const port = chunk.readUInt16BE(portIdx);
    let addrIdx = portIdx + 2;
    let addrLen = 0;
    let addrValIdx = addrIdx + 1;
    let hostname = '';
    const addressType = chunk[addrIdx];

    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = [...chunk.subarray(addrValIdx, addrValIdx + addrLen)].join('.');
            break;
        case 2:
            addrLen = chunk[addrValIdx];
            addrValIdx += 1;
            hostname = chunk.subarray(addrValIdx, addrValIdx + addrLen).toString('utf8');
            break;
        case 3: {
            addrLen = 16;
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(chunk.readUInt16BE(addrValIdx + i * 2).toString(16));
            }
            hostname = ipv6.join(':');
            break;
        }
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }

    if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };

    return {
        hasError: false,
        addressType,
        port,
        hostname,
        isUDP,
        rawIndex: addrValIdx + addrLen,
        version,
    };
}

function waitForSocketEvent(socket, eventName, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
        const cleanup = () => {
            clearTimeout(timer);
            socket.off(eventName, onReady);
            socket.off('error', onError);
        };
        const onReady = () => {
            cleanup();
            resolve();
        };
        const onError = (error) => {
            cleanup();
            reject(error);
        };
        const timer = setTimeout(() => {
            cleanup();
            socket.destroy();
            reject(new Error('connection timeout'));
        }, timeoutMs);

        socket.once(eventName, onReady);
        socket.once('error', onError);
    });
}

async function createTcpSocket(host, port) {
    const socket = net.connect({ host, port });
    await waitForSocketEvent(socket, 'connect');
    return socket;
}

async function createTlsSocket(host, port) {
    const socket = tls.connect({
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
    });
    await waitForSocketEvent(socket, 'secureConnect');
    return socket;
}

class SocketReader {
    constructor(socket) {
        this.socket = socket;
        this.buffers = [];
        this.length = 0;
        this.ended = false;
        this.error = null;
        this.waiters = [];
        this.onData = (chunk) => this.push(chunk);
        this.onEnd = () => {
            this.ended = true;
            this.wake();
        };
        this.onError = (error) => {
            this.error = error;
            this.wake();
        };
        socket.on('data', this.onData);
        socket.once('end', this.onEnd);
        socket.once('error', this.onError);
    }

    push(chunk) {
        this.buffers.push(Buffer.from(chunk));
        this.length += chunk.length;
        this.wake();
    }

    wake() {
        const waiters = this.waiters.splice(0);
        for (const waiter of waiters) waiter();
    }

    async wait(timeoutMs) {
        if (this.error) throw this.error;
        if (this.length > 0) return;
        if (this.ended) throw new Error('socket closed');

        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                cleanup();
                reject(new Error('read timeout'));
            }, timeoutMs);
            const cleanup = () => {
                clearTimeout(timer);
                const index = this.waiters.indexOf(done);
                if (index !== -1) this.waiters.splice(index, 1);
            };
            const done = () => {
                cleanup();
                resolve();
            };
            this.waiters.push(done);
        });
    }

    take(size) {
        const out = Buffer.allocUnsafe(size);
        let offset = 0;

        while (offset < size) {
            const chunk = this.buffers[0];
            const need = size - offset;
            if (chunk.length <= need) {
                chunk.copy(out, offset);
                offset += chunk.length;
                this.buffers.shift();
                this.length -= chunk.length;
            } else {
                chunk.copy(out, offset, 0, need);
                this.buffers[0] = chunk.subarray(need);
                offset += need;
                this.length -= need;
            }
        }

        return out;
    }

    takeAll() {
        if (this.length === 0) return Buffer.alloc(0);
        return this.take(this.length);
    }

    async read(size, timeoutMs = 10000) {
        while (this.length < size) {
            await this.wait(timeoutMs);
        }
        return this.take(size);
    }

    async readUntil(needle, maxBytes = 8192, timeoutMs = 10000) {
        while (this.length <= maxBytes) {
            const buffer = Buffer.concat(this.buffers, this.length);
            const index = buffer.indexOf(needle);
            if (index !== -1) {
                return this.take(index + needle.length);
            }
            await this.wait(timeoutMs);
        }
        throw new Error('response header too large');
    }

    release() {
        this.socket.off('data', this.onData);
        this.socket.off('end', this.onEnd);
        this.socket.off('error', this.onError);
        return this.takeAll();
    }
}

async function connectDirect(targetHost, targetPort) {
    return { socket: await createTcpSocket(targetHost, targetPort), leftover: Buffer.alloc(0) };
}

async function connect2Socks5(proxyConfig, targetHost, targetPort) {
    const socket = await createTcpSocket(proxyConfig.host, proxyConfig.port);
    const reader = new SocketReader(socket);

    try {
        const hasAuth = Boolean(proxyConfig.username || proxyConfig.password);
        socket.write(hasAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]));

        const methodResponse = await reader.read(2);
        if (methodResponse[0] !== 0x05) {
            throw new Error('S5 method selection failed');
        }

        if (methodResponse[1] === 0x02) {
            const userBytes = Buffer.from(proxyConfig.username);
            const passBytes = Buffer.from(proxyConfig.password);
            if (userBytes.length > 255 || passBytes.length > 255) {
                throw new Error('S5 username or password is too long');
            }
            socket.write(Buffer.concat([
                Buffer.from([0x01, userBytes.length]),
                userBytes,
                Buffer.from([passBytes.length]),
                passBytes,
            ]));
            const authResponse = await reader.read(2);
            if (authResponse[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (methodResponse[1] !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${methodResponse[1]}`);
        }

        const hostBytes = Buffer.from(targetHost);
        if (hostBytes.length > 255) {
            throw new Error('target host is too long');
        }

        const portBytes = Buffer.alloc(2);
        portBytes.writeUInt16BE(targetPort);
        socket.write(Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
            hostBytes,
            portBytes,
        ]));

        const responseHead = await reader.read(4);
        if (responseHead[1] !== 0x00) {
            throw new Error(`S5 connection failed: ${responseHead[1]}`);
        }

        if (responseHead[3] === 0x01) {
            await reader.read(4);
        } else if (responseHead[3] === 0x03) {
            const len = await reader.read(1);
            await reader.read(len[0]);
        } else if (responseHead[3] === 0x04) {
            await reader.read(16);
        } else {
            throw new Error(`S5 invalid address type: ${responseHead[3]}`);
        }
        await reader.read(2);

        return { socket, leftover: reader.release() };
    } catch (error) {
        reader.release();
        socket.destroy();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort) {
    const socket = proxyConfig.type === 'https'
        ? await createTlsSocket(proxyConfig.host, proxyConfig.port)
        : await createTcpSocket(proxyConfig.host, proxyConfig.port);
    const reader = new SocketReader(socket);

    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        if (proxyConfig.username || proxyConfig.password) {
            const auth = Buffer.from(`${proxyConfig.username}:${proxyConfig.password}`).toString('base64');
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        connectRequest += 'User-Agent: Node.js\r\n';
        connectRequest += 'Connection: keep-alive\r\n\r\n';

        socket.write(connectRequest);
        const headerBuffer = await reader.readUntil(Buffer.from('\r\n\r\n'));
        const statusLine = headerBuffer.toString('latin1').split('\r\n')[0];
        const statusMatch = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d+)/i);

        if (!statusMatch) {
            throw new Error(`Invalid HTTP proxy response: ${statusLine}`);
        }

        const statusCode = Number(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`HTTP proxy CONNECT failed: ${statusLine}`);
        }

        return { socket, leftover: reader.release() };
    } catch (error) {
        reader.release();
        socket.destroy();
        throw error;
    }
}

async function openRemoteConnection(proxyConfig, targetHost, targetPort) {
    if (!proxyConfig) {
        return connectDirect(targetHost, targetPort);
    }

    if (proxyConfig.type === 'socks5') {
        return connect2Socks5(proxyConfig, targetHost, targetPort);
    }

    if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
        return connect2Http(proxyConfig, targetHost, targetPort);
    }

    throw new Error(`Unsupported proxy type: ${proxyConfig.type}`);
}

class WebSocketConnection {
    constructor(socket, head) {
        this.socket = socket;
        this.readyState = WebSocketConnection.OPEN;
        this.buffer = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
        this.fragments = [];
        this.fragmentOpcode = 0;
        this.onMessage = null;
        this.onClose = null;
        this.onError = null;
        this.closeHandlers = new Set();

        socket.on('data', (chunk) => this.handleData(chunk));
        socket.once('end', () => this.closeLocal());
        socket.once('close', () => this.closeLocal());
        socket.once('error', (error) => {
            if (this.onError) this.onError(error);
            this.closeLocal();
        });

        if (this.buffer.length) {
            this.parseFrames();
        }
    }

    handleData(chunk) {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.parseFrames();
    }

    parseFrames() {
        while (this.buffer.length >= 2) {
            const first = this.buffer[0];
            const second = this.buffer[1];
            const fin = Boolean(first & 0x80);
            const opcode = first & 0x0f;
            const masked = Boolean(second & 0x80);
            let payloadLen = second & 0x7f;
            let offset = 2;

            if (payloadLen === 126) {
                if (this.buffer.length < offset + 2) return;
                payloadLen = this.buffer.readUInt16BE(offset);
                offset += 2;
            } else if (payloadLen === 127) {
                if (this.buffer.length < offset + 8) return;
                const high = this.buffer.readUInt32BE(offset);
                const low = this.buffer.readUInt32BE(offset + 4);
                if (high > 0x1fffff) {
                    this.close(1009);
                    return;
                }
                payloadLen = high * 2 ** 32 + low;
                offset += 8;
            }

            if (!masked) {
                this.close(1002);
                return;
            }

            if (this.buffer.length < offset + 4 + payloadLen) return;

            const mask = this.buffer.subarray(offset, offset + 4);
            offset += 4;
            const payload = Buffer.from(this.buffer.subarray(offset, offset + payloadLen));
            this.buffer = this.buffer.subarray(offset + payloadLen);

            for (let i = 0; i < payload.length; i++) {
                payload[i] ^= mask[i % 4];
            }

            if (opcode === 0x8) {
                this.close();
                return;
            }
            if (opcode === 0x9) {
                this.sendFrame(payload, 0x0a);
                continue;
            }
            if (opcode === 0x0) {
                this.fragments.push(payload);
                if (fin) {
                    const message = Buffer.concat(this.fragments);
                    this.fragments = [];
                    this.emitMessage(message);
                }
                continue;
            }
            if (opcode !== 0x1 && opcode !== 0x2) {
                continue;
            }

            if (fin) {
                this.emitMessage(payload);
            } else {
                this.fragmentOpcode = opcode;
                this.fragments = [payload];
            }
        }
    }

    emitMessage(message) {
        if (this.onMessage) this.onMessage(message);
    }

    send(data) {
        this.sendFrame(Buffer.from(data), 0x2);
    }

    sendFrame(payload, opcode) {
        if (this.readyState !== WebSocketConnection.OPEN) return;

        let header;
        if (payload.length < 126) {
            header = Buffer.from([0x80 | opcode, payload.length]);
        } else if (payload.length <= 0xffff) {
            header = Buffer.alloc(4);
            header[0] = 0x80 | opcode;
            header[1] = 126;
            header.writeUInt16BE(payload.length, 2);
        } else {
            header = Buffer.alloc(10);
            header[0] = 0x80 | opcode;
            header[1] = 127;
            header.writeUInt32BE(0, 2);
            header.writeUInt32BE(payload.length, 6);
        }

        this.socket.write(Buffer.concat([header, payload]));
    }

    close(code = 1000) {
        if (this.readyState === WebSocketConnection.CLOSED) return;
        if (this.readyState === WebSocketConnection.OPEN) {
            const payload = Buffer.alloc(2);
            payload.writeUInt16BE(code);
            this.sendFrame(payload, 0x8);
        }
        this.readyState = WebSocketConnection.CLOSING;
        this.closeLocal();
        this.socket.end();
        setTimeout(() => {
            if (!this.socket.destroyed) {
                closeSocketQuietly(this.socket);
            }
        }, 1000).unref();
    }

    addCloseHandler(handler) {
        this.closeHandlers.add(handler);
        return () => this.closeHandlers.delete(handler);
    }

    closeLocal() {
        if (this.readyState === WebSocketConnection.CLOSED) return;
        this.readyState = WebSocketConnection.CLOSED;
        if (this.onClose) this.onClose();
        for (const handler of this.closeHandlers) {
            try {
                handler();
            } catch (_) {}
        }
        this.closeHandlers.clear();
    }
}

WebSocketConnection.OPEN = 1;
WebSocketConnection.CLOSING = 2;
WebSocketConnection.CLOSED = 3;

function closeSocketQuietly(socket) {
    try {
        socket.destroy();
    } catch (_) {}
}

function bridgeRemoteToWebSocket(remoteSocket, ws, respHeader, leftover) {
    let header = respHeader;
    let closed = false;

    const cleanup = () => {
        if (closed) return;
        closed = true;
        remoteSocket.off('data', sendChunk);
        closeSocketQuietly(remoteSocket);
    };

    const sendChunk = (chunk) => {
        if (ws.readyState !== WebSocketConnection.OPEN) {
            cleanup();
            return;
        }
        if (header) {
            ws.send(Buffer.concat([header, Buffer.from(chunk)]));
            header = null;
        } else {
            ws.send(chunk);
        }
    };

    if (leftover && leftover.length) {
        sendChunk(leftover);
    }

    remoteSocket.on('data', sendChunk);
    remoteSocket.once('end', () => ws.close());
    remoteSocket.once('close', () => ws.close());
    remoteSocket.once('error', () => ws.close());
    ws.addCloseHandler(cleanup);
}

async function forwardUDP(udpChunk, webSocket, respHeader) {
    let socket;
    let closed = false;
    let timeout;

    const cleanup = () => {
        if (closed) return;
        closed = true;
        if (timeout) clearTimeout(timeout);
        if (socket) {
            socket.removeAllListeners('data');
            closeSocketQuietly(socket);
        }
    };

    const removeWsCloseHandler = webSocket.addCloseHandler(cleanup);

    try {
        socket = await createTcpSocket('8.8.8.8', 53);
        let header = respHeader;
        let responseBuffer = Buffer.alloc(0);

        timeout = setTimeout(cleanup, 10000);
        timeout.unref();

        socket.on('data', (chunk) => {
            if (timeout) timeout.refresh();
            if (webSocket.readyState !== WebSocketConnection.OPEN) return;
            responseBuffer = Buffer.concat([responseBuffer, Buffer.from(chunk)]);
            if (header) {
                webSocket.send(Buffer.concat([header, Buffer.from(chunk)]));
                header = null;
            } else {
                webSocket.send(chunk);
            }

            if (responseBuffer.length >= 2) {
                const responseLength = responseBuffer.readUInt16BE(0);
                if (responseLength > 0 && responseBuffer.length >= responseLength + 2) {
                    cleanup();
                    removeWsCloseHandler();
                }
            }
        });
        socket.once('close', removeWsCloseHandler);
        socket.once('error', () => {
            removeWsCloseHandler();
            webSocket.close();
        });
        socket.write(udpChunk);
    } catch (_) {
        cleanup();
        removeWsCloseHandler();
        webSocket.close();
    }
}

async function handleVlessWebSocket(ws, earlyDataHeader, proxyConfig) {
    let remoteSocket = null;
    let isDnsQuery = false;
    let writeQueue = Promise.resolve();

    ws.addCloseHandler(() => {
        if (remoteSocket) closeSocketQuietly(remoteSocket);
    });

    async function handleChunk(chunk) {
        if (isDnsQuery) {
            await forwardUDP(chunk, ws, null);
            return;
        }

        if (remoteSocket) {
            remoteSocket.write(chunk);
            return;
        }

        const parsed = parseWsPacketHeader(chunk, yourUUID);
        if (parsed.hasError) {
            throw new Error(parsed.message);
        }

        if (parsed.isUDP) {
            if (parsed.port === 53) {
                isDnsQuery = true;
            } else {
                throw new Error('UDP is not supported');
            }
        }

        const respHeader = Buffer.from([parsed.version[0], 0]);
        const rawData = chunk.subarray(parsed.rawIndex);

        if (isDnsQuery) {
            await forwardUDP(rawData, ws, respHeader);
            return;
        }

        const { socket, leftover } = await openRemoteConnection(proxyConfig, parsed.hostname, parsed.port);
        remoteSocket = socket;
        if (ws.readyState !== WebSocketConnection.OPEN) {
            closeSocketQuietly(remoteSocket);
            return;
        }
        bridgeRemoteToWebSocket(remoteSocket, ws, respHeader, leftover);
        if (rawData.length) {
            remoteSocket.write(rawData);
        }
    }

    ws.onMessage = (chunk) => {
        writeQueue = writeQueue.then(() => handleChunk(Buffer.from(chunk))).catch((error) => {
            console.error(error.message);
            ws.close();
            if (remoteSocket) closeSocketQuietly(remoteSocket);
        });
    };

    const earlyData = base64ToBuffer(earlyDataHeader);
    if (earlyData && earlyData.length) {
        ws.onMessage(earlyData);
    }
}

function acceptWebSocket(req, socket, head) {
    const key = req.headers['sec-websocket-key'];
    if (!key) {
        socket.destroy();
        return;
    }

    const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
    const headers = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${accept}`,
    ];

    const protocol = req.headers['sec-websocket-protocol'];
    if (protocol) {
        headers.push(`Sec-WebSocket-Protocol: ${protocol.split(',')[0].trim()}`);
    }

    socket.write(`${headers.join('\r\n')}\r\n\r\n`);

    const proxyConfig = getProxyFromRequestPath(req.url);
    if (proxyConfig) {
        console.log(`outbound proxy: ${proxyConfig.type}://${proxyConfig.host}:${proxyConfig.port}`);
    } else {
        console.log('outbound proxy: direct');
    }

    const ws = new WebSocketConnection(socket, head);
    handleVlessWebSocket(ws, protocol || '', proxyConfig).catch((error) => {
        console.error(error.message);
        ws.close();
    });
}

const server = http.createServer((req, res) => {
    res.writeHead(req.url === '/' ? 200 : 404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(req.url === '/' ? 'socks2vless is running\n' : 'Not Found\n');
});

server.on('upgrade', (req, socket, head) => {
    if ((req.headers.upgrade || '').toLowerCase() !== 'websocket') {
        socket.destroy();
        return;
    }
    acceptWebSocket(req, socket, head);
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    console.log(`socks2vless listening on ${LISTEN_HOST}:${LISTEN_PORT}`);
    console.log(`uuid: ${yourUUID}`);
    console.log('proxy path examples:');
    console.log('/socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080');
    console.log('/socks5://user:password@127.0.0.1:1080');
    console.log('/http://user:password@127.0.0.1:8080');
    console.log('/https://user:password@127.0.0.1:8080');
});
