const http2 = require('http2');
const fs = require('fs');
const crypto = require('crypto');

class APIService {
  constructor() {
    this.server = null;
    this.router = new Router();
    this.users = Object.values(this.loadUsersFromFile());
    this.sessionDuration = 600 * 1000;
    this.rateLimits = new Map(); // IP bazlı rate limit verilerini depolamak için kullanılan harita
    this.maxRequestsPerMinute = 16; // Dakika başına maksimum istek sayısı
    this.rateLimitDuration = 60 * 1000; // Rate limit süresi (milisaniye cinsinden)
    this.maxConnections = 8; // Maksimum eşzamanlı bağlantı sayısı
    this.connectionBandwidth = 1000; // Bağlantı başına ayrılan bant genişliği (örnekte 1 KB/s)
    this.connections = new Map(); // Aktif bağlantıları takip etmek için bir harita
  }

  handleRequest(req, res) {
    const method = req.method;
    const url = req.url;
  
    // Rate limit kontrolü yapılıyor
    const ipAddress = req.socket.remoteAddress;
    if (this.checkRateLimit(ipAddress)) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 429; // Too Many Requests
      res.end(JSON.stringify({
        success: false,
        statusCode: 429,
        message: 'too many request'
      }));
      return;
    }

    if (this.connections.size >= this.maxConnections) {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 503; // Service Unavailable
      res.end(JSON.stringify({ success: false, statusCode: 503, message: 'server is currently busy' }));
      return;
    }
  
    // Bağlantıyı takip et
    const connectionId = crypto.randomUUID(); // Her bağlantı için benzersiz bir kimlik oluştur
    const connection = { req, res };
    this.connections.set(connectionId, connection);
  
    // Rate limit kontrolü ve diğer işlemler
  
    // Bağlantı sona erdiğinde takibi kaldır
    req.on('close', () => {
      this.connections.delete(connectionId);
    });
  
    const route = this.router.matchRoute(method, url, true);
  
    if (route) {
      const handler = route.handler;
      handler(req, res, route.params);
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 404;
      res.end(JSON.stringify({"success": false, "statusCode": 404, "message": "not found"}));
    }
  }  

  checkBandwidth(connection) {
    const currentTimestamp = Date.now();
    const bandwidthUsed = this.calculateBandwidthUsage();
  
    // Bağlantı başına düşen bant genişliğini hesapla
    const connectionBandwidth = this.connectionBandwidth / this.maxConnections;
  
    // Mevcut bağlantılarla birlikte bağlantı başına düşen bant genişliğini kontrol et
    if (bandwidthUsed + connectionBandwidth > this.connectionBandwidth) {
      return false; // Bant genişliği aşıldı
    }
  
    // Bağlantı bant genişliği kullanımını güncelle
    this.updateBandwidthUsage(connectionBandwidth);
  
    return true;
  }
  
  calculateBandwidthUsage() {
    let totalUsage = 0;
    this.connections.forEach((connection) => {
      // Bağlantıların toplam bant genişliği kullanımını hesapla
      // İsteğin boyutuna veya süresine göre bant genişliği kullanımını tahmin edebilirsin
      totalUsage += calculateUsageForConnection(connection);
    });
    return totalUsage;
  }
  
  updateBandwidthUsage(usage) {
    this.connections.forEach((connection) => {
      // Bağlantıların bant genişliği kullanımını güncelle
      // İsteğin boyutuna veya süresine göre bant genişliği kullanımını tahmin edebilirsin
      updateUsageForConnection(connection, usage);
    });
  }

  checkRateLimit(ipAddress) {
    const now = Date.now();
  
    if (!this.rateLimits.has(ipAddress)) {
      // İlk kez gelen bir IP adresi için rate limit verilerini oluştur
      this.rateLimits.set(ipAddress, {
        count: 1,
        timestamp: now
      });
      return false;
    }
  
    const rateLimit = this.rateLimits.get(ipAddress);
  
    // Geçen süre kontrol ediliyor
    if (now - rateLimit.timestamp > this.rateLimitDuration) {
      // Rate limit süresi dolmuş, verileri güncelle
      rateLimit.count = 1;
      rateLimit.timestamp = now;
      return false;
    }
  
    // Rate limit kontrolü
    if (rateLimit.count >= this.maxRequestsPerMinute) {
      return true;
    }
  
    // Rate limit sınırı aşılmadı, verileri güncelle
    rateLimit.count++;
    this.rateLimits.set(ipAddress, rateLimit);
    return false;
  }

  start(port) {
    const options = {
      key: fs.readFileSync('ssl/key.pem'),
      cert: fs.readFileSync('ssl/cert.pem'),
      allowHTTP1: true,
      keepAlive: true,

      sessionTimeout: 600 * 1000
    };

    this.server = http2.createSecureServer(options, this.handleRequest.bind(this));

    this.server.listen(port, () => {
      console.log(`API service is running on port ${port}`);
    });
  }

  logoutHandler(req, res) {
    res.setHeader('Set-Cookie', 'access_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    res.setHeader('Content-Type', 'text/html');
    res.statusCode = 200;
    res.end('logout successful<br><a href="/referanse">return</a> <a href="/login">login</a>');
  }

  authenticateRequest(req) {
    const authHeader = req.headers.authorization;
    const cookieHeader = req.headers.cookie;
    let jwt = null;
  
    if (authHeader) {
      const [type, credentials] = authHeader.split(' ');
  
      if (type === 'Bearer') {
        jwt = credentials;
      }
    } else if (cookieHeader) {
      const jwtCookie = cookieHeader
        .split(';')
        .map(row => row.trim())
        .find(row => row.startsWith('access_token='));
  
      if (jwtCookie) {
        jwt = jwtCookie.slice('access_token='.length);
      }
    }
  
    if (jwt) {
      const users = this.getUsersFromFile();
      const payload = this.verifyJWT(req, jwt, users);
  
      if (payload) {
        return payload;
      }
    }
  
    return null;
  }

  loadUsersFromFile() {
    try {
      const fileData = fs.readFileSync('services/data/users.json', 'utf-8');
      const users = JSON.parse(fileData);
      return users;
    } catch (error) {
      console.error('file read error:', error);
      return {};
    }
  }

  getUserRole(userId) {
    const userPermission = this.getUsersFromFile().find((permission) => permission.userId === userId);
    if (userPermission) {
      return userPermission.role;
    }
    return null; // Kullanıcıya ait bir rol bulunamadıysa null dönebilirsiniz
  }

  deleteMessage(uuid) {
    const filePath = `services/data/questioning/${uuid}.json`;
  
    return new Promise((resolve, reject) => {
      fs.unlink(filePath, error => {
        if (error) {
          console.error('file deletion error:', error);
          reject(false);
        } else {
          console.log('message deleted successfullyi:', uuid);
          resolve(true);
        }
      });
    });
  }
  
  saveUsersToFile() {
    const jsonData = JSON.stringify(this.users, null, 2);

    fs.writeFile('services/data/users.json', jsonData, error => {
      if (error) {
        console.error('file read error:', error);
      } else {
        console.log('users have been successfully registered');
      }
    });
  }

  getUsersFromFile() {
    try {
      const fileData = fs.readFileSync('services/data/users.json', 'utf-8');
      const users = JSON.parse(fileData);
      return users;
    } catch (error) {
      console.error('file read error:', error);
      return [];
    }
  }

  getUserMessagesForId(userId) {
    const fileNames = fs.readdirSync('services/data/questioning');
    const jsonFiles = fileNames.filter(fileName => fileName.endsWith('.json'));
    const userMessages = [];
  
    jsonFiles.forEach(fileName => {
      const fileData = fs.readFileSync(`services/data/questioning/${fileName}`, 'utf-8');
      const parsedData = JSON.parse(fileData);
      if (parsedData.userId === userId) {
        userMessages.push(parsedData);
      }
    });
  
    return userMessages;
  } 

  addUser(username, email, password, userId, token, salt) {
    const lowerCaseUsername = username.toLowerCase();
    const existingUser = this.users.find(user => user.username.toLowerCase() === lowerCaseUsername);
    if (existingUser) {
      console.error('username already exists.');
      return;
    }
  
    const user = {
      username: username,
      email: email,
      password: password,
      userId: userId,
      secret: token,
      salt: salt,
      timestamp: new Date().getTime('tr-TR', { timeZone: 'Europe/Istanbul'}),
      role: 'user'
    };
  
    this.users.push(user);
    this.saveUsersToFile();
  }
  

  verifyPassword(password, savedHash, savedSalt) {
    const hashedPassword = crypto
      .pbkdf2Sync(password, savedSalt, 1000, 32, 'sha3-512')
      .toString('hex');
  
    const savedHashBuffer = Buffer.from(savedHash, 'hex');
    const hashedPasswordBuffer = Buffer.from(hashedPassword, 'hex');
  
    if (savedHashBuffer.length !== hashedPasswordBuffer.length) {
      return false; // Hatalı hex değerleri, şifreler eşleşmiyor
    }
  
    return crypto.timingSafeEqual(savedHashBuffer, hashedPasswordBuffer);
  }  
  
  createSaltPassword(password, salt) {
    const hashedPassword = crypto
    .pbkdf2Sync(password, salt, 1000, 32, 'sha3-512')
    .toString('hex');

    return hashedPassword
  }

  addRoute(method, path, handler, options = {}) {
    const { authenticate = false } = options;
    this.router.addRoute(method, path, this.authenticateHandler(handler, authenticate));
  }

  connect(url, headers, payload = null) {
    const client = http2.connect(url);
    client.on('error', (error) => console.error('http2 connection error:', error));
  
    client.on('connect', () => {
      const request = client.request(headers);
      let responseData = '';
  
    //   request.on('response', (responseHeaders) => {
    //     console.log('Yanıt başlıkları:', responseHeaders);
    //   });
  
      request.on('data', (chunk) => {
        responseData += chunk;
      });
  
      request.on('end', () => {
        try {
            console.error('response:', JSON.parse(responseData));
        } catch (error) {
          console.error('JSON syntax error:', error);
        }
        client.close();
      });
  
      if (payload) {
        request.setEncoding('utf-8');
        request.write(JSON.stringify(payload));
      }
      request.end();
    });
  }

  createJWT(user, ip) {
    const header = {
      alg: 'HS512',
      typ: 'JWT'
    };

    const payload = {
      username: user.username,
      email: user.email,
      userId: user.userId,
      role: user.role,
      ip: ip,
      exp: new Date().getTime('tr-TR', { timeZone: 'Europe/Istanbul'}) + this.sessionDuration // Oturumun sona erme zamanı
    };

    const headerBase64 = Buffer.from(JSON.stringify(header)).toString('base64');
    const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64');

    const signature = crypto.createHmac('sha3-512', user.secret)
      .update(`${headerBase64}.${payloadBase64}`)
      .digest('base64');

    const jwt = `${headerBase64}.${payloadBase64}.${signature}`;
    return jwt;
  }

  verifyJWT(req, jwt) {
    const [headerBase64, payloadBase64, signature] = jwt.split('.');
    const user = this.getUsersFromFile().find(u => u.secret === this.getUserSecret(payloadBase64));
  
    if (!user) {
      return null;
    }
  
    const calculatedSignature = crypto.createHmac('sha3-512', user.secret)
      .update(`${headerBase64}.${payloadBase64}`)
      .digest('base64');
  
    if (calculatedSignature === signature) {
      const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
  
      // IP kontrolü yapılıyor
      if (payload.ip === req.socket.remoteAddress && payload.exp > new Date().getTime('tr-TR', { timeZone: 'Europe/Istanbul'})) {
        return payload;
      }
    }
  
    return null;
  }

  getUserSecret(payloadBase64) {
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
    const user = this.getUsersFromFile().find(u => u.userId === payload.userId && u.email === payload.email);
    return user ? user.secret : null;
  }

  authenticateHandler(handler, authenticate) {
    if (authenticate) {
      return (req, res, params) => {
        const paylaod = this.authenticateRequest(req);
  
        if (!paylaod) {
          res.setHeader('WWW-Authenticate', 'Bearer realm="API"');
          res.setHeader('Content-Type', 'application/json');
          res.statusCode = 401;
          res.end(JSON.stringify({"success": false, "statusCode": 401, "message": "unauthorization"}));
          return;
        } 
  
        handler(req, res, params, paylaod);
      };
    } else {
      return handler;
    }
  }
}

class Router {
  constructor() {
    this.routes = [];
  }

  addRoute(method, path, handler, authenticate) {
    this.routes.push({ method, path, handler, authenticate });
  }

  matchRoute(method, url, allowDelete) {
    const urlSegments = url.split('/');
    for (const route of this.routes) {
      const routeSegments = route.path.split('/');
      if (route.method === method && routeSegments.length === urlSegments.length) {
        let match = true;
        const params = {};
        for (let i = 0; i < routeSegments.length; i++) {
          if (routeSegments[i] !== urlSegments[i] && !routeSegments[i].startsWith(':')) {
            match = false;
            break;
          } else if (routeSegments[i].startsWith(':')) {
            const paramName = routeSegments[i].substring(1);
            params[paramName] = urlSegments[i];
          }
        }
        if (match && (allowDelete || route.method !== 'DELETE')) {
          return { ...route, params };
        }
      }
    }
    return null;
  }
  
}


module.exports = { APIService, Router }