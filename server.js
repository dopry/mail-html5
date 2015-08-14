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
                //log.http('express', line);
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
            hostname: os.hostname().split('.')[0],
            port: 143,
            secure: false,
            requireTLS: true,
            ignoreTLS: false
        },
        smtp: {
            hostname: os.hostname().split('.')[0],
            port: 587,
            secure: false,
            requireTLS: true,
            ignoreTLS: false
        }
    };
    res.status(200).json(response);
});


var keys = {};
var keysById = {};


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
    console.log('looking up email!', email);
    if (!keys.hasOwnProperty(email)) {
        return res.status(404).json({"error":"Public key not found"});
    }
    return res.status(200).json(keys[email]);
});

/// PUT publickey/user/admin@example.org/key/AF3DB54BE8D443A5
var jsonBodyParser = bodyParser.json();
app.put('/publickey/user/:email/key/:keyId', jsonBodyParser, function(req, res, next) {
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


    keys[email] = [body];
    keysById[body._id] = body;

    // Their service sends an email with an account verification key here.
    // TODO: we need to generate an email the verifier can pick up.
    return res.status(200).send();
});

app.get('/publickey/key/:id', function(req, res, next) {
    log.info('PUT key', 'Request for %s, %s', req.params.email, req.params.keyId);
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Cache-control', 'no-cache');
    var id = req.params.id;
    if (!keysById.hasOwnProperty(id)) {
        return res.status(404).json({"error":"Public key not found"});
    }
    return res.status(200).json(keysById[id]);
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