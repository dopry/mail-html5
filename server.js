'use strict';

process.chdir(__dirname);

var cluster = require('cluster');
var config = require('config');
var log = require('npmlog');
var os = require('os');

log.level = config.log.level;

// Handle error conditions
process.on('SIGTERM', function() {
    log.warn('exit', 'Exited on SIGTERM');
    process.exit(0);
});

process.on('SIGINT', function() {
    log.warn('exit', 'Exited on SIGINT');
    process.exit(0);
});

process.on('uncaughtException', function(err) {
    log.error('uncaughtException ', err);
    process.exit(1);
});

if (cluster.isMaster) {
    // MASTER process

    cluster.on('fork', function(worker) {
        log.info('cluster', 'Forked worker #%s [pid:%s]', worker.id, worker.process.pid);
    });

    cluster.on('exit', function(worker) {
        log.warn('cluster', 'Worker #%s [pid:%s] died', worker.id, worker.process.pid);
        setTimeout(function() {
            cluster.fork();
        }, 1000);
    });

    // Fork a single worker
    cluster.fork();
    return;
}

//  WORKER process

var express = require('express');
var bodyParser = require('body-parser');
var compression = require('compression');
var app = express();
var server = require('http').Server(app);
var io = require('socket.io')(server);
var net = require('net');

// Setup logger. Stream all http logs to general logger
app.use(require('morgan')(config.log.http, {
    'stream': {
        'write': function(line) {
            if ((line = (line || '').trim())) {
                log.http('express', line);
            }
        }
    }
}));

// Do not advertise Express
app.disable('x-powered-by');

//
// web server config
//

var development = (process.argv[2] === '--dev');

// autodiscovery - default mail server settings.
app.get('/autodiscovery/:domain', function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Cache-control', 'no-cache');
    var response = {
        domain: req.params.domain,
        imap: {
            hostname: process.env.IMAP_HOST || 'localhost',
            port: process.env.IMAP_PORT || 143,
            secure: false,
            requireTLS: true,
            ignoreTLS: false
        },
        smtp: {
            hostname: process.env.SMTP_HOST || 'localhost',
            port: process.env.SMTP_PORT || 587,
            secure: false,
            requireTLS: true,
            ignoreTLS: false
        }
    };
    res.status(200).json(response);
});


var keys = {
    'dopry@test.com': {
        public_keys: {
            'idsjkdhfl':
                    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                    "Version: SKS 1.1.5\n" +
                    "Comment: Hostname: keyserver.ubuntu.com\n" +
                    "\n" +
                    "mQGiBEhIO8ERBADanj8UO/01iHFxya7JnsOtJo+D3DZHNKy/ISm2VacnRSeuHAqR0ppdhInV" +
                    "nTbRlDvilQFHbQF/eKXQy4qFn67oYYAUXmTwEAPNZwxypYbpm41eB8FeJ8BD6T9Ib/8hBqf1" +
                    "Zzik8C2xsVfSg2pY4MmdQKEwE3PQ7IW65dQEh/pxiwCgt069W2QQcXsd2N1RPiMqIE5X2d8D" +
                    "/1U+w1H1vYLAHaucCSficZ10MHbQei5jitIH1xSYGZrrxyOfiZUp/+jqMYYvpa/5en+a06lw" +
                    "55a9Hq6tdce5H4PS9/YHqJgE/rfmbGF1CY3khwIVYNf8oCPIaPa/4n0GpPHthVRCXe/x4Mig" +
                    "MwchqzKzhx/DVYJt/gGNhJjbOlE6A/9NfwCdEfY15xYMMDzgEQuCC2E8qoTCGAJrsEX3Wj2n" +
                    "jLQm8Kv3lj7W4WhhyO+8/wUlOoD58OAqY7VqwQvFpBgri6C3k+LS4s9sHF3hUNl6Qi6ViJf3" +
                    "+h3rAfxNe0KLpwWJmKbtDfT88wXyZ6oeLT0i5eVcKuqQohKTl3sAgiqD0LQsRGFycmVsIE8n" +
                    "UHJ5IChkb3ByeSkgPGRhcnJlbC5vcHJ5QGdtYWlsLmNvbT6IYAQTEQIAIAUCSEg7wQIbAwYL" +
                    "CQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEO73BtI8iLGkvfcAn0cSPgLdUp1qkvLkB8kcSQjV" +
                    "yXCMAJ4ySz+u+Ku1MpgKQxhB3aUUcuOEYbkCDQRISDvOEAgAmymbjTY1wlT6Jwu+iT8FP6qQ" +
                    "Mspx/uIE0JgprgdVEZaAKpyAxHPAQ0S58SmfutNAt70y5m9IaTlAVUM1elgJhzGcP8YoFGtq" +
                    "dLY05ijP4dKF2xTct1qZOgRg6Jne8lB7xug4FWMz4PMK4AUNsqr8a4K02XN7IE4WvkU6agOo" +
                    "7y8FvL7ybe7/T6O72A6lDhwciKxi6X8fCLejwvfiqapJuQFIJ5Lmia03J1Frb8UGQLlZXyNq" +
                    "B6BfyvPBug58P9/YRpH6nkJeXF99E4+ILOgbtKRvKb1dqpwp1QQ0t3c4+o56kXkPZwqQPrYb" +
                    "Ul5QV7nmNHSVhoIgHfRUD/UvXUN67wADBQf+NvcImyvUNE9voP8UYz4y58hRsFdpUqT45xSB" +
                    "0xa80oDlffxVCQVUyEl4rgebaOJ360SYGwwCAd9VA80NtPSXd5QG5oqdX1JVBonUmw2edDmO" +
                    "HGzWrJSRNgaapNlXXFGZRMqWlFr4zXWzsoT7WEYtoRyz7acg+20AYpkNh6pArvISiiMXKdk5" +
                    "YXGccq4PUyxz1UVLaELlucpen/7RCI0Ci3aJGCZ2FaVmogD0U1lBPfJ3Tdjj8YL1eH3IxCkC" +
                    "dXy9mQoYGnIXuDXFHtI/IOOIcXC08U/NeekU1TN7svCIFb5x0rYrkHFvDOJvXHQ1YhRrdriS" +
                    "NG1VqVh3UHtSwkzc0ohJBBgRAgAJBQJISDvOAhsMAAoJEO73BtI8iLGkbX0AoI5C2MImYmrh" +
                    "ou5NKI2FjjMs+MX4AJ4rmwxj9timGrav/smjTgk46LlYTQ==" +
                    "=Di3i\n" +
                    "-----END PGP PUBLIC KEY BLOCK-----"
        }
    }
};
var idxKeysId = {};

// key server.
app.get('/publickey/user/:email', function (req, res, next) {
    // get: https://keys.whiteout.io/publickey/user/mail.support@whiteout.io
    // [{"_id":"EE342F0DDBB0F3BE","userId":"mail.support@whiteout.io","publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: OpenPGP.js v.1.20131205\r\nComment: Whiteout Mail - http://whiteout.io\r\n\r\nxsBNBFLeWSABCADCNCMzMuFQu+hM9nu4tfyIdiyM/sCEhJa/iauzIlhS9Lun\ns0TnO5EF1pSM6CskFBegoA1fSOcRz1oalrZ2xPrVWdvEGf1NmfWEGM3mzaSa\nwRVZLHwPwkIYacobIa7gPeWJslUwSPVD8Yqz3BMXjp9kVcE7u/pgL2dUvg6w\nfBJM2ZJ5+2KJqsk7xhZpL3A0b+kc22srxQZsSQhgOJr0mAtJsjmLv1r/ZtNk\nZ2ktEQgCreHL1Am1dBZcNYB8cUyW0oqvyoA0ZHyRUM8BcOXNYIWAnlzWx99+\n8Adt5Q/07Qo0fy8uZLD/oUiGqDroBPx4QJgv8lbbPXteIQzMqaL/LjMRABEB\nAAHNKFdoaXRlb3V0IFVzZXIgPG1haWwuc3VwcG9ydEB3aGl0ZW91dC5pbz7C\nwFwEEAEIABAFAlLeWSIJEO40Lw3bsPO+AAA33wgApSgBINYWV7oajy8g5Cvx\nP4AmQTLqWrAFgY3wQ3rmyDUoHfS/ohyXQipi9Cyq4kymF6WGf1KGGhjPQosl\nPX9jQGIpJxAGAaV86NEN0gmmou0w7ERHhcCfBbkZPoumggeTkKb9+kCe7KXM\npP9iXfW7sw7ry63KjosLLP3b8aSmfRC5GtpK2Ifo921ubuJc2GvY4cHRWYiU\nSqr2RVj9a4tqBkDiSMcMnVFXaW64I1gXoiqWTtCeQbe4ywoy+AuLfnKs3Uq7\nVMv5ws7QTAacrtJxChJVcjojVAQ7um0H7lUxbXaKOi3Aj3mJQnplqCcEIkTj\nWCZV9w8HRoMPOaIxY7xViw==\r\n=9iZ9\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n"}]
    log.info('keys', 'Request for %s', req.params.email);
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Cache-control', 'no-cache');

    //return res.status(200).json({});
    var email = req.params.email;
    if (!keys.hasOwnProperty(email)) {
        return res.status(404).json({"error":"Public key not found"});
    }
    var user = keys[email];

    return res.status(200).send(user);

});

/// PUT publickey/user/admin@example.org/key/AF3DB54BE8D443A5
var jsonBodyParser = bodyParser.json();
app.put('/publickey/user/:email/key/:keyId', jsonBodyParser, function() {
    log.info('PUT key', 'Request for %s, %s', req.params.email, req.params.keyId);
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Cache-control', 'no-cache');

    var email = req.params.email;
    var keyId = req.params.keyId;
    var body = req.body;
    // {
    //     "_id":"AF3DB54BE8D443A5",
    //     "userId":"admin@example.org",
    //     "publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: OpenPGP.js v1.2.0\r\nComment: Whiteout Mail - https://whiteout.io\r\n\r\nxsBNBFXFFmABCADN8pqnrXg3pSu/avImZyD2umI745XX83vh6evOiYPQcpf/\nEUx0MtrpoAl8pv+N+xKg1otFuqLb3PNSzDSmo9UPE/T/nc9TPX1ijXs2oDUy\na+ada43KZLExliTcyCC8epJGkn18fteUODG8EaPwFWdZNtteoNTQKecIa1gY\nPWQsMKgXOv1kFpkct6QT0wR+fsTkANtoPLD4aK/2RyTl4nN9HYPCm9Oqw208\nLkiltszytc8uubryJc5AGhkANlfEM3N0GFIWk+D9vzl+vAEXwwHPDMTi1wXt\nn+0vqwTXIMgJq98XNXr9Y1Mx5/IW04zAWhf/7Ht/enqGGmh2fJiVjrQ3ABEB\nAAHNFCA8YWRtaW5AZXhhbXBsZS5vcmc+wsByBBABCAAmBQJVxRZgBgsJCAcD\nAgkQrz21S+jUQ6UEFQgCCgMWAgECGwMCHgEAANkjCACuYbpDNSmAkdsAr/ho\n9HOV9fINFDt1meeysJAkNTgJvTJfXyp54BLrkmi4jp5sCUEfrnGb7VsZ5pK6\nEq2URlbPLtok9h3++vDwdKPHrWJip+X7ACjSIRAUoZ3YYNkHdy7+iuNE818r\nYyYWw6s8TXLVjcyOXunNe14R45I5XZImZEpt9R+D1yfTJfi/vd+SjNKCukUC\nZNbRdukzkE6tDx4zVCgE/fwLl+lQ1tSRMRJGx+5MS/flQjHhzF8yxIUdwzqL\nDqou0iT+qHNkBOnvyACaTM+7TXnoGxHrLeFsJEQ5a7/FWX6Emn7g66cgmC2t\nGeFB6P9W1N5Qsqv/LVeXRgw6zsBNBFXFFmABCAC8BbMHhI9ZZQa/NUiQJ2T5\nhS3eZyNHPxuxN44mfLSm8FTIVRrl7TxDvSapY/rLipDZ6ZSElmzIpZkXuwW3\nrzDaGWkdn0i7oHBQ+UNXdZNwbw08ftQPbv3OT7NytmRemDIL+gBN7FnUp5Gz\njX/NMz4dBrwIS2n2pWWGphIadfYnJTYCUz++X323IeINZDv/BUykPOQtPosj\nYecbiBTgG1Nro0S4YTtnnaRemPjnxHXEXn3C7hkjtzFmNJ73r+ZWpecgMtzd\n6W2DJh5aYkoqZhZb2bRGEFPEuQp3z9crYdWxCv87n2NF7PXZFJ2EbpdXcySf\n7IW4ZdVQItGh9xmu5IhNABEBAAHCwF8EGAEIABMFAlXFFmEJEK89tUvo1EOl\nAhsMAABR+QgAiQeE5x/xqrjveDMWfk2PX+Y2AyXYndxSIdn+asgC7zxQ1nkx\nb0qbZ2Gb5Krhgz37916y5U8rbarRb/kg81HGxNncexQZdimE5XJT3ytzAttV\nXecfio1oEj8LSSC+bgYNOxxRMSSG9rPL/UNvZ8I84dppeWdV7TsNwbbd/XKN\nxXkzbG6TCQqVOsTd1aamDK+BsG6W8Q/pvX/F9ZpHGFovz808/2rdDlJSHL0d\nauVN0no5w6oAoDUYH3Zja6G0V3gUBTsrax3F4YBkk5WkcyLO5dIAMPRwZ/si\nveZ/WrC5CCyqS1IK7cNLFqN/Z+eiUJBx4OML90i0dxGhrHxVo9fTOA==\r\n=Jvh3\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n\r\n"
    // }

    if (keyId != body._id) {
        res.status(500).json({"error":"id mismatch"});
    }
    if (email != body.userId) {
        res.status(500).json({"error":"userid mismatch"});
    }


    if (!keys[email]) {
        keys[email] = {
            public_keys: {},
            revoked_keys: {}
        }
    }
    keys[email].public_keys[keyId] = body.publicKey;
    // Their service sends an email with an account verification key here.
    // TODO: we need to generate an email the verifier can pick up.
    return res.status(200).send();
});

// https://keys.whiteout.io/verify/ec128900-7189-4f65-85fa-d57394a9e212
// {"msg":"Verification successful"}

// set HTTP headers
app.use(function(req, res, next) {
    // prevent rendering website in foreign iframe (Clickjacking)
    res.set('X-Frame-Options', 'DENY');
    // HSTS
    res.set('Strict-Transport-Security', 'max-age=16070400; includeSubDomains');
    // CSP
    var iframe = development ? "http://" + req.hostname + ":" + config.server.port : "https://" + req.hostname; // allow iframe to load assets
    var csp = "default-src 'self' " + iframe + "; object-src 'none'; connect-src *; style-src 'self' 'unsafe-inline' " + iframe + "; img-src *";
    res.set('Content-Security-Policy', csp);
    res.set('X-Content-Security-Policy', csp);
    // set Cache-control Header (for AppCache)
    res.set('Cache-control', 'public, max-age=0');
    next();
});
app.use('/service-worker.js', noCache);
app.use('/appcache.manifest', noCache);

function noCache(req, res, next) {
    res.set('Cache-control', 'no-cache');
    next();
}
app.use('/tpl/read-sandbox.html', function(req, res, next) {
    res.set('X-Frame-Options', 'SAMEORIGIN');
    next();
});

// redirect all http traffic to https
app.use(function(req, res, next) {
    if ((!req.secure) && (req.get('X-Forwarded-Proto') !== 'https') && !development) {
        res.redirect('https://' + req.hostname + req.url);
    } else {
        next();
    }
});

// use gzip compression
app.use(compression());

// server static files
app.use(express.static(__dirname + '/dist'));

//
// Socket.io proxy
//

io.on('connection', function(socket) {
    log.info('io', 'New connection [%s] from %s', socket.conn.id, socket.conn.remoteAddress);

    socket.on('open', function(data, fn) {
        if (!development && config.server.outboundPorts.indexOf(data.port) < 0) {
            log.info('io', 'Open request to %s:%s was rejected, closing [%s]', data.host, data.port, socket.conn.id);
            socket.disconnect();
            return;
        }

        log.verbose('io', 'Open request to %s:%s [%s]', data.host, data.port, socket.conn.id);
        var tcp = net.connect(data.port, data.host, function() {
            log.verbose('io', 'Opened tcp connection to %s:%s [%s]', data.host, data.port, socket.conn.id);

            tcp.on('data', function(chunk) {
                log.silly('io', 'Received %s bytes from %s:%s [%s]', chunk.length, data.host, data.port, socket.conn.id);
                socket.emit('data', chunk);
            });

            tcp.on('error', function(err) {
                log.verbose('io', 'Error for %s:%s [%s]: %s', data.host, data.port, socket.conn.id, err.message);
                socket.emit('error', err.message);
            });

            tcp.on('end', function() {
                socket.emit('end');
            });

            tcp.on('close', function() {
                log.verbose('io', 'Closed tcp connection to %s:%s [%s]', data.host, data.port, socket.conn.id);
                socket.emit('close');

                socket.removeAllListeners('data');
                socket.removeAllListeners('end');
            });

            socket.on('data', function(chunk, fn) {
                if (!chunk || !chunk.length) {
                    if (typeof fn === 'function') {
                        fn();
                    }
                    return;
                }
                log.silly('io', 'Sending %s bytes to %s:%s [%s]', chunk.length, data.host, data.port, socket.conn.id);
                tcp.write(chunk, function() {
                    if (typeof fn === 'function') {
                        fn();
                    }
                });
            });

            socket.on('end', function() {
                log.verbose('io', 'Received request to close connection to %s:%s [%s]', data.host, data.port, socket.conn.id);
                tcp.end();
            });

            if (typeof fn === 'function') {
                fn(os.hostname());
            }

            socket.on('disconnect', function() {
                log.verbose('io', 'Closed connection [%s], closing connection to %s:%s ', socket.conn.id, data.host, data.port);
                tcp.end();
                socket.removeAllListeners();
            });
        });
    });
});

//
// start server
//

server.listen(config.server.port);
if (development) {
    console.log(' > starting in development mode');
}
console.log(' > listening on http://localhost:' + config.server.port + '\n');