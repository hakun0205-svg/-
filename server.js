const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const port = 3000;
const postsFile = path.join(__dirname, 'posts.json');
const usersFile = path.join(__dirname, 'users.json');
const sessionsFile = path.join(__dirname, 'sessions.json');

function loadJSON(file, defaultValue) {
  if (!fs.existsSync(file)) {
    return defaultValue;
  }

  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return defaultValue;
  }
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function loadPosts() {
  return loadJSON(postsFile, []).map(post => ({
    ...post,
    id: post.id || generateId()
  }));
}

function savePosts(posts) {
  saveJSON(postsFile, posts.map(post => ({
    ...post,
    id: post.id || generateId()
  })));
}

function loadUsers() {
  return loadJSON(usersFile, []);
}

function saveUsers(users) {
  saveJSON(usersFile, users);
}

function loadSessions() {
  return loadJSON(sessionsFile, []);
}

function saveSessions(sessions) {
  saveJSON(sessionsFile, sessions);
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function createToken() {
  return crypto.randomBytes(16).toString('hex');
}

function generateId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function getSession(token) {
  if (!token) {
    return null;
  }

  const sessions = loadSessions();
  return sessions.find(session => session.token === token) || null;
}

function parseIdToken(idToken) {
  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) return null;
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload;
  } catch {
    return null;
  }
}

function parseJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const decoded = Buffer.from(parts[1], 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'POST' && url.pathname === '/api/apple-login') {
    try {
      const body = JSON.parse(await readBody(req));
      const idToken = String(body.idToken || '').trim();
      const user = body.user || {};

      if (!idToken) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ID トークンが必要です。' }));
        return;
      }

      const payload = parseJwt(idToken);
      if (!payload || !payload.sub) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ID トークンが無効です。' }));
        return;
      }

      const appleId = String(payload.sub);
      const email = payload.email ? String(payload.email).toLowerCase() : `${appleId}@appleid.local`;
      const username = user.name ? `${user.name.firstName || ''} ${user.name.lastName || ''}`.trim() : `Apple User ${appleId.slice(0, 8)}`;
      
      let users = loadUsers();
      let userRecord = users.find(item => item.appleId === appleId);

      if (!userRecord) {
        userRecord = {
          id: Date.now(),
          email,
          username,
          password: null,
          appleId
        };
        users.push(userRecord);
        saveUsers(users);
      }

      const token = createToken();
      const sessions = loadSessions();
      sessions.push({ token, username: userRecord.username });
      saveSessions(sessions);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true, token, username: userRecord.username }));
    } catch (error) {
      console.error('Apple login error:', error);
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'Apple ログイン处理中でエラーが発生しました。' }));
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/google-login') {
    try {
      const body = JSON.parse(await readBody(req));
      const idToken = String(body.idToken || '').trim();

      if (!idToken) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ID トークンが必要です。' }));
        return;
      }

      const payload = parseIdToken(idToken);
      if (!payload || !payload.email) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ID トークンが無効です。' }));
        return;
      }

      const email = String(payload.email).toLowerCase();
      const username = payload.name || email.split('@')[0];
      
      let users = loadUsers();
      let user = users.find(item => item.email === email);

      if (!user) {
        user = {
          id: Date.now(),
          email,
          username,
          password: null,
          googleId: payload.sub
        };
        users.push(user);
        saveUsers(users);
      }

      const token = createToken();
      const sessions = loadSessions();
      sessions.push({ token, username: user.username });
      saveSessions(sessions);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true, token, username: user.username }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'Google ログイン处理中でエラーが発生しました。' }));
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/posts') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(loadPosts()));
    return;
  }

  if (req.method === 'POST' && url.pathname.startsWith('/api/posts/') && url.pathname.endsWith('/edit')) {
    const segments = url.pathname.split('/').filter(Boolean);
    const postId = segments[2];
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    try {
      const body = JSON.parse(await readBody(req));
      const message = String(body.message || '').trim();
      if (!message) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: '編集内容を入力してください。' }));
        return;
      }

      const posts = loadPosts();
      const targetPost = posts.find(post => post.id === postId);
      if (!targetPost || targetPost.name !== session.username) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: '自分の投稿だけを編集できます。' }));
        return;
      }

      targetPost.message = message;
      savePosts(posts);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: '編集内容が正しくありません。' }));
    }
    return;
  }

  if (req.method === 'POST' && url.pathname.startsWith('/api/posts/') && url.pathname.endsWith('/like')) {
    const segments = url.pathname.split('/').filter(Boolean);
    const postId = segments[2];
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    const posts = loadPosts();
    const targetPost = posts.find(post => post.id === postId);
    if (!targetPost) {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: '対象の投稿が見つかりません。' }));
      return;
    }

    targetPost.likes = Number(targetPost.likes || 0) + 1;
    savePosts(posts);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ success: true, likes: targetPost.likes }));
    return;
  }

  if (req.method === 'POST' && url.pathname.startsWith('/api/posts/') && url.pathname.endsWith('/reply')) {
    const segments = url.pathname.split('/').filter(Boolean);
    const postId = segments[2];
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    try {
      const body = JSON.parse(await readBody(req));
      const message = String(body.message || '').trim();
      if (!message) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: '返信内容を入力してください。' }));
        return;
      }

      const posts = loadPosts();
      const targetPost = posts.find(post => post.id === postId);
      if (!targetPost) {
        res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: '対象の投稿が見つかりません。' }));
        return;
      }

      targetPost.replies = targetPost.replies || [];
      targetPost.replies.push({
        name: session.username,
        message,
        time: new Date().toLocaleString('ja-JP')
      });
      savePosts(posts);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: '返信内容が正しくありません。' }));
    }
    return;
  }

  if (req.method === 'DELETE' && url.pathname.startsWith('/api/posts/')) {
    const segments = url.pathname.split('/').filter(Boolean);
    const postId = segments[2];
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    const posts = loadPosts();
    const index = posts.findIndex(post => post.id === postId);
    if (index === -1 || posts[index].name !== session.username) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: '自分の投稿だけを削除できます。' }));
      return;
    }

    posts.splice(index, 1);
    savePosts(posts);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/me') {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ success: true, username: session.username }));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/account/update') {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    try {
      const body = JSON.parse(await readBody(req));
      const newUsername = String(body.username || '').trim();
      const currentPassword = String(body.currentPassword || '').trim();
      const newPassword = String(body.newPassword || '').trim();

      if (!currentPassword) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: '現在のパスワードを入力してください。' }));
        return;
      }

      if (!newUsername && !newPassword) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ユーザー名または新しいパスワードを入力してください。' }));
        return;
      }

      const users = loadUsers();
      const user = users.find(item => item.username === session.username);

      if (!user || user.password !== hashPassword(currentPassword)) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: '現在のパスワードが違います。' }));
        return;
      }

      let nextUsername = session.username;
      if (newUsername) {
        if (newUsername !== session.username && users.some(item => item.username === newUsername)) {
          res.writeHead(409, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'そのユーザー名はすでに使われています。' }));
          return;
        }
        nextUsername = newUsername;
      }

      user.username = nextUsername;
      if (newPassword) {
        user.password = hashPassword(newPassword);
      }
      saveUsers(users);

      const sessions = loadSessions();
      sessions.forEach(item => {
        if (item.username === session.username) {
          item.username = nextUsername;
        }
      });
      saveSessions(sessions);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true, username: nextUsername }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'アカウント設定の更新に失敗しました。' }));
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/register') {
    try {
      const body = JSON.parse(await readBody(req));
      const username = String(body.username || '').trim();
      const password = String(body.password || '').trim();

      if (!username || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ユーザー名とパスワードを入力してください。' }));
        return;
      }

      const users = loadUsers();
      if (users.some(user => user.username === username)) {
        res.writeHead(409, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'そのユーザー名はすでに使われています。' }));
        return;
      }

      const newUser = {
        id: Date.now(),
        username,
        password: hashPassword(password)
      };
      users.push(newUser);
      saveUsers(users);

      const token = createToken();
      const sessions = loadSessions();
      sessions.push({ token, username });
      saveSessions(sessions);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true, token, username }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: '登録内容が正しくありません。' }));
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/login') {
    try {
      const body = JSON.parse(await readBody(req));
      const username = String(body.username || '').trim();
      const password = String(body.password || '').trim();

      const users = loadUsers();
      const user = users.find(item => item.username === username && item.password === hashPassword(password));

      if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: 'ユーザー名またはパスワードが違います。' }));
        return;
      }

      const token = createToken();
      const sessions = loadSessions();
      sessions.push({ token, username });
      saveSessions(sessions);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true, token, username }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログイン情報が正しくありません。' }));
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/posts') {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const session = getSession(token);

    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'ログインが必要です。' }));
      return;
    }

    try {
      const body = JSON.parse(await readBody(req));
      const posts = loadPosts();
      posts.push({
        id: generateId(),
        name: session.username,
        message: String(body.message || '').trim(),
        time: body.time || new Date().toLocaleString('ja-JP'),
        replies: [],
        likes: 0
      });
      savePosts(posts);

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: true }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: '投稿内容が正しくありません。' }));
    }
    return;
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    const htmlPath = path.join(__dirname, 'index.html');
    fs.readFile(htmlPath, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Error reading index.html');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ success: false, error: 'Not found' }));
});

server.listen(port, () => {
  console.log(`掲示板サーバー起動: http://localhost:${port}`);
});
