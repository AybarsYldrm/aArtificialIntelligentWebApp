const tls = require('tls');

class SMTPService {
  constructor(options) {
    this.host = options.host;
    this.port = options.port || 465;
    this.username = options.username;
    this.password = options.password;
  }

  send(options) {
    const from = options.from;
    const to = options.to;
    const subject = options.subject || '';
    const message = options.message || '';

    const tlsOptions = {
      host: this.host,
      port: this.port,
      secure: true,
      rejectUnauthorized: true // Sertifika doğrulamasını etkinleştir
    };

    const client = tls.connect(tlsOptions, () => {
      console.log('connected to smtp server');
    });

    client.on('error', (error) => {
      console.error('error:', error);
    });

    let isAuthLoginRequired = true; // Varsayılan olarak "AUTH LOGIN" gereklidir

    client.on('data', (data) => {
      const responseCode = data.toString().substr(0, 3);
      console.log('server response:', data.toString());

      if (responseCode === '220') {
        client.write(`HELO ${this.host}\r\n`);
      } else if (responseCode === '250') {
        if (isAuthLoginRequired) {
          client.write(`AUTH LOGIN\r\n`);
        }
      } else if (responseCode === '334') {
        if (data.toString().includes('VXNlcm5hbWU6')) {
          client.write(`${Buffer.from(this.username, 'utf-8').toString('base64')}\r\n`);
        } else if (data.toString().includes('UGFzc3dvcmQ6')) {
          client.write(`${Buffer.from(this.password, 'utf-8').toString('base64')}\r\n`);
        }
      } else if (responseCode === '235') {
        client.write(`MAIL FROM: <${from}>\r\n`);
        client.write(`RCPT TO: <${to}>\r\n`);
        client.write(`DATA\r\n`);
        isAuthLoginRequired = false; // E-posta gönderme aşamasına geçildi, "AUTH LOGIN" gerekliliği kalkar
      } else if (responseCode === '354') {
        const emailContent = `Subject: ${subject}\r\nFrom: ${from}\r\nTo: ${to}\r\nContent-Type: text/html\r\n\r\n${message}\r\n.\r\n`;
        client.write(emailContent);
        client.write(`QUIT\r\n`);
      } else if (responseCode === '250') {
        client.write('QUIT\r\n');
      }
    });

    client.on('end', () => {
      console.log('smtp server connection ended');
    });
  }
}

module.exports = { SMTPService }