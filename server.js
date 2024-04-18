const crypto = require('crypto');
const fs = require('fs');
const { predictSentiment } = require('./services/brain_service.js')
const { APIService } = require('./services/main_services.js')
const { SMTPService } = require('./services/smtp_service.js')

const apiService = new APIService();
const smtpService = new SMTPService({
  host: 'smtp.gmail.com',
  port: 465,
  username: '<EMAIL>',
  password: '<GOOGLEAPPLICATIONKEY>'
})
const url = 'https://discord.com';
const token = 'Bot <TOKEN>'

apiService.addRoute('POST', '/questioning', (req, res) => {
  let data = '';

  req.on('data', chunk => {
    data += chunk;
  });

  req.on('end', () => {
    const payload = apiService.authenticateRequest(req);
    const postData = JSON.parse(data.toString());
    const query = postData.query
    const sentiment = predictSentiment(postData.query);
    const uuid = crypto.randomUUID();
    const schema = {
      text: query,
      date: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', timeZoneName: 'short' }),
      uuid: uuid,
      sentiment: sentiment,
      username: payload.username,
      userId: payload.userId,
      role: payload.role
    };

    smtpService.send({
      from: '<EMAIL>',
      to: payload.email,
      subject: 'API referanse',
      message: `
      <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name=description content="a web site that we try to develop at
         a simple level and complete the deficiencies (beta)">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        </head>
        <body>
        <img src="https://cdn.discordapp.com/avatars/717748467174342686/9f256366c439056ed954d4c4482d8858" alt=image">
          <p>
            <strong>Hello ${payload.username} (${payload.userId}) this is your</strong>
          </p>
          <p>answers to your questions for artificial intelligence:</p>
          <pre>text: ${query}</pre>
          <pre>sentiment: ${sentiment}</pre>
          <br>
          <p>if you want, you can go to your profile and review it</p>
          <p><a href="https://192.168.1.16/profile">profile</a></p>
          <p>${new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', timeZoneName: 'short' })}</p>
        </body>
        </html>
      `,
    })

    const content = {
      "embeds": [
        {
          "author": {
            "name": "Aybars Yildirim",
            "url": "https://192.168.1.16",
            "icon_url": "https://lh3.googleusercontent.com/ogw/AOLn63Hdo4jV9KGZ3VpqA_YjoYP1b5aCN6-r-I4dByI0FA=s32-c-mo"
          },
          "title": "API Referanse",
          "url": "https://192.168.1.16/referanse",
          "description": "basit entegrasyonlu yapay zeka algoritmamın sonuçlarıyla denemelerini buradan izleyebilirsiniz",
          "color": 16777215,
          "fields": [
            {
              "name": "message",
              "value": query,
              "inline": true
            },
            {
              "name": "sentiment",
              "value": sentiment,
              "inline": true
            }          
          ],
          // "thumbnail": {
          //   "url": ""
          // },
          // "image": {
          //   "url": ""
          // },
          "footer": {
            "text": `user: ${payload.username} id: ${payload.userId} message_id: ${uuid} ${new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', timeZoneName: 'short' })}`,
            "icon_url": "https://cdn.discordapp.com/attachments/857360162590294066/1124446700887625768/image.jpg"
          }
        }
      ],
      "components": [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "label": "API referanse",
                    "style": 5,
                    "url": "https://192.168.1.16/referanse"
                }
            ]

        }
    ]
    }

    const userRole = apiService.getUserRole(payload.userId)

    if(userRole === 'admin') {
      apiService.connect(url, {
        ':method': 'POST',
        ':path': '/api/v10/channels/<CHANNELID>/messages', // Gönderilecek URL'nin yolu
        'Authorization': `${token}`,
        'Content-Type': 'application/json'
      }, content)
    }


    fs.appendFile(`services/data/questioning/${uuid}.json`, JSON.stringify(schema), error => {
      if (error) {
        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 500;
        res.end(
          JSON.stringify({
            success: false,
            statusCode: 500,
            message: 'something went wrong'
          })
        );
        return;
      }

      if (query) {
        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 201
        res.end(
          JSON.stringify({
            success: true,
            statusCode: 201,
            message: sentiment,
            uuid: uuid
          })
        );
      } else {
        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 400
        res.end(
          JSON.stringify({
            success: false,
            statusCode: 400,
            message: 'there was an error sending the query'
          })
        );
      }
    });
  });
}, { authenticate: true });

apiService.addRoute('GET', '/questioning/:uuid', (req, res, params) => {
  const { uuid } = params;

  fs.readFile(`services/data/questioning/${uuid}.json`, 'utf-8', (error, data) => {
    if (error) {
      console.error('file read error:', error);
      res.statusCode = 404;
      res.end('not found');
    } else {
      const parsedData = JSON.parse(data);
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 200;
      res.end(JSON.stringify(parsedData));
    }
  });
});

apiService.addRoute('DELETE', '/questioning/:uuid', async (req, res, params) => {
  const { uuid } = params;
  
  try {
    const success = await apiService.deleteMessage(uuid);

    if (success) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 201
      res.end(JSON.stringify({ success: true, statusCode: 201, message: 'message deleted successfully' }));
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 404
      res.end(JSON.stringify({ success: false, statusCode: 404, message: 'message not found' }));
    }
  } catch (error) {
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 500
    res.end(JSON.stringify({ success: false, statusCode: 500, message: 'something went wrong' }));
  }
}, { authenticate: true });

apiService.addRoute('GET', '/referanse', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/index.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.statusCode = 200
  res.end(htmlFile);
});

apiService.addRoute('GET', '/login', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/login.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.statusCode = 200
  res.end(htmlFile);
});

apiService.addRoute('POST', '/login', (req, res) => {
  let data = '';
  req.on('data', (chunk) => {
    data += chunk;
  });
  req.on('end', () => {
    const postData = JSON.parse(data.toString());

    const email = postData.email;
    const password = postData.password;

    const users = apiService.getUsersFromFile();
    const matchedUser = users.find(u => u.email === email);

    if (!email || !password) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 400;
      res.end(
        JSON.stringify({
          success: false,
          statusCode: 400,
          message: 'email or password are required'
        })
      );
      return; // İşlemi sonlandırın
    }
  
    if (!matchedUser || !apiService.verifyPassword(password, matchedUser.password, matchedUser.salt)) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 401;
      res.end(
        JSON.stringify({
          success: false,
          statusCode: 401,
          message: 'invalid email or password'
        })
      );
      return; // İşlemi sonlandırın
    }

    const ip = req.socket.remoteAddress;
    const jwt = apiService.createJWT(matchedUser, ip);

    res.setHeader('Set-Cookie', `access_token=${jwt}; HttpOnly; Max-Age=${6000 * 1000 / 1000}; Secure;`);
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 201;
    res.end(
      JSON.stringify({
        success: true,
        statusCode: 201,
        message: 'user login successful'
      })
    );
  });
});

apiService.addRoute('GET', '/about', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/about.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.statusCode = 200
  res.end(htmlFile);
});

apiService.addRoute('GET', '/discover', (req, res) => {
  const fileNames = fs.readdirSync('services/data/questioning');
  const jsonFiles = fileNames.filter(fileName => fileName.endsWith('.json'));
  const usersMessages = [];

  jsonFiles.forEach(fileName => {
    const fileData = fs.readFileSync(`services/data/questioning/${fileName}`, 'utf-8');
    const parsedData = JSON.parse(fileData);
    usersMessages.push(parsedData);
  });

  const html = generateDiscoverPage(usersMessages);

  res.setHeader('Content-Type', 'text/html');
  res.statusCode = 200
  res.end(html);
});

apiService.addRoute('GET', '/logout', apiService.logoutHandler.bind(apiService), { authenticate: true });

apiService.addRoute('GET', '/profile', (req, res) => {
  const payload = apiService.authenticateRequest(req);
  const userMessages = apiService.getUserMessagesForId(payload.userId);
  const html = generateProfilePage(payload, userMessages);
    res.setHeader('Content-Type', 'text/html');
    res.statusCode = 200
    res.end(html);
}, { authenticate: true });


apiService.addRoute('GET', '/create', (req, res) => {
  const htmlFile = fs.readFileSync('services/page/create.html', 'utf-8');

  res.setHeader('Content-Type', 'text/html');
  res.statusCode = 200
  res.end(htmlFile);
});

apiService.addRoute('POST', '/create', (req, res, params) => {
  let data = '';

  req.on('data', chunk => {
    data += chunk;
  });

  req.on('end', () => {
    const postData = JSON.parse(data.toString());

    // Kullanıcı adı ve şifreyi alın
    const username = postData.username;
    const email = postData.email;
    const password = postData.password;

    if (!username || !email || !password) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 400;
      res.end(
        JSON.stringify({
          success: false,
          statusCode: 400,
          message: 'username, email and password are required'
        })
      );
      return; // İşlemi sonlandırın
    }
    
    // Kullanıcı adının minimum uzunluk kontrolü
    const MIN_USERNAME_LENGTH = 4;
    if (username.length < MIN_USERNAME_LENGTH) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 400;
      res.end(
        JSON.stringify({
          success: false,
          statusCode: 400,
          message: `username must be at least ${MIN_USERNAME_LENGTH} characters long`
        })
      );
      return; // İşlemi sonlandırın
    }

    const existingUser = apiService.users.find(user => user.username.toLowerCase() === username.toLowerCase() || user.email.toLowerCase() === email.toLowerCase());
    if (existingUser) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 409;
      res.end(
        JSON.stringify({
          success: false,
          statusCode: 409,
          message: 'username or email already exists'
        })
      );
      return; // İşlemi sonlandırın
    }

    // Şifrenin karmaşıklık kontrolü
    const isStrongPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;

    if (!isStrongPassword.test(password)) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 400;
      res.end(
        JSON.stringify({
          success: false,
          statusCode: 400,
          message: 'password must meet the complexity requirements'
        })
      );
      return; // İşlemi sonlandırın
    }

    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!isEmail.test(email)) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 400;
      res.end(JSON.stringify({
        success: false,
        statusCode: 400,
        message: 'invalid email format'
      }));
      return;
    }

    else {
      const salt = crypto.randomBytes(16).toString('hex');
      const userId = crypto.randomBytes(8).toString('hex');
      const token = crypto.createHmac('sha3-512', password + salt).update(username + userId).digest('hex');
      const hashedPassword = apiService.createSaltPassword(password, salt)

      apiService.addUser(username, email, hashedPassword, userId, token, salt);
      smtpService.send({
        from: '<EMAIL>',
        to: email,
        subject: 'API referanse',
        message: `
        <!DOCTYPE html>
          <html lang="en">
          <head>
          <meta charset="UTF-8">
          <meta name=description content="a web site that we try to develop at
           a simple level and complete the deficiencies (beta)">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <meta http-equiv="X-UA-Compatible" content="IE=edge">
          </head>
          <body>
            <p>
              <strong>Hello ${username} (${userId}) this is your</strong>
            </p>
            <p>please click the following link to lookup API referanse:</p>
            <p><a href="https://192.168.1.16/referanse">API referanse</a></p>
            <p>${new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', timeZoneName: 'short' })}</p>
          </body>
          </html>
        `,
      })

      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 201
      res.end(
        JSON.stringify({
          success: true,
          statusCode: 201,
          message: 'user registered successfully'
        })
      );
    }
  });
});

function generateDiscoverPage(usersMessages) {
  let html = '<html><head><meta charset="UTF-8"><title>discover page</title></head><body><h1>discover page</h1>';
  html += '<br><a href="/referanse">return</a></body></html>';
  usersMessages.forEach(data => {
    
    const allowedProperties = ['text', 'date', 'sentiment', 'username', 'role'];
    html += '<hr>'; // Paragraf aralarına çizgi ekliyoruz
    for (const key in data) {
      if (key !== 'uuid' && allowedProperties.includes(key)) {
        html += `<p><strong>${key}:</strong> ${data[key]}</p>`; // Sadece izin verilen özellikleri paragraf olarak ekliyoruz
      }
    }
  });
  return html
}

function generateProfilePage(payload, userMessages) {
  let html = `<html><head><meta charset="UTF-8"><title>profile page</title></head><body><h1>hello ${payload.username} (${payload.role})</h1>`;
  html += `<p>your id: ${payload.userId}</p>`
  html += '<br><a href="/referanse">return</a></body></html>';

  userMessages.forEach(data => {
    const allowedProperties = ['text', 'date', 'sentiment', 'username', 'role'];
    html += '<hr>'; // Paragraf aralarına çizgi ekliyoruz
    for (const key in data) {
      if (key !== 'uuid' && allowedProperties.includes(key)) {
        html += `<p><strong>${key}:</strong> ${data[key]}</p>`; // Sadece izin verilen özellikleri paragraf olarak ekliyoruz
      }
    }
  
    html += `<button onclick="deleteMessage('${data.uuid}')">delete</button>`;
  });
  html += `<script>async function deleteMessage(uuid) {
    try {
      const response = await fetch('questioning/'+ uuid, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        console.log('ok');
      }
    } catch (error) {
     console.error(error);
    }
  }
  </script>`
  return html;
}

apiService.start(443);
