// server/src/scanners/SSLScanner.js
const BaseScanner = require('./BaseScanner');
const tls = require('tls');
const Vulnerability = require('../models/vulnerability.model');

class SSLScanner extends BaseScanner {
    constructor() {
        super('SSL');
    }

    async startScan(target) {
        let results = [];

        try {
            const sslDetails = await this.getSSLDetails(target);

            if (sslDetails.validFrom && sslDetails.validTo) {
                const now = new Date();
                if (now < sslDetails.validFrom || now > sslDetails.validTo) {
                    await this.saveVulnerability({
                        name: 'Expired or Invalid Certificate',
                        description: 'The SSL certificate is expired or not yet valid.',
                        impact: 'High',
                        confidence: 'High',
                        location: target
                    });
                    results.push('Certificate is expired or not yet valid.');
                }
            }

            const weakCiphers = this.checkWeakCiphers(sslDetails.ciphers);
            if (weakCiphers.length > 0) {
                await this.saveVulnerability({
                    name: 'Weak SSL Ciphers',
                    description: `The server supports weak ciphers: ${weakCiphers.join(', ')}`,
                    impact: 'Medium',
                    confidence: 'High',
                    location: target
                });
                results.push(`Supports weak ciphers: ${weakCiphers.join(', ')}`);
            }

            if (results.length === 0) {
                results.push('No SSL vulnerabilities found.');
            }
        } catch (error) {
            results.push(`Error scanning SSL vulnerabilities: ${error.message}`);
        }

        const finalResult = results.join('\n');
        this.logResult(finalResult);
        return finalResult;
    }

    async saveVulnerability(vulnData) {
        const vulnerability = new Vulnerability(vulnData);
        await vulnerability.save();
    }

    getSSLDetails(target) {
        return new Promise((resolve, reject) => {
            const url = new URL(target);
            const options = {
                host: url.hostname,
                port: 443,
                servername: url.hostname,
            };

            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate(true);
                if (socket.authorized || cert) {
                    const ciphers = socket.getCipher();
                    const sslDetails = {
                        validFrom: new Date(cert.valid_from),
                        validTo: new Date(cert.valid_to),
                        ciphers: [ciphers.name],
                    };
                    resolve(sslDetails);
                } else {
                    reject(new Error('Unable to get SSL certificate details.'));
                }
                socket.end();
            });

            socket.on('error', (err) => {
                reject(err);
            });
        });
    }

    checkWeakCiphers(ciphers) {
        const weakCiphersList = [
            'EXP-', 'NULL', 'LOW', 'DES', 'RC4', 'MD5', 'PSK', 'SRP', 'CAMELLIA', 'SEED', '3DES'
        ];

        return ciphers.filter(cipher =>
            weakCiphersList.some(weakCipher => cipher.includes(weakCipher))
        );
    }
}

module.exports = SSLScanner;
