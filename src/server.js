
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuid } = require('uuid');



const app = express();


app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
const upload = multer();

const users = [];
const photos = [
  {
    id: uuid(),
    url: "https://picsum.photos/900/600",
    title: "Welcome to SnapFlow",
    creator: "SnapFlow Team",
    reactions: { like: 4, love: 3, wow: 2, sad: 0 },
    comments: [{ user: "Admin", text: "Enjoy the flow 🚀" }],
    shares: 2
  }
];

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.sendStatus(401);
  try {
    req.user = jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: "Invalid password" });
  }
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: "User exists" });

  users.push({
    id: uuid(),
    name,
    email,
    role,
    password: await bcrypt.hash(password, 10)
  });
  res.json({ message: "Registered" });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, role: user.role, name: user.name },
    process.env.JWT_SECRET
  );
  res.json({ token, role: user.role });
});

app.post('/api/photos', auth, upload.single('image'), (req, res) => {
  if (req.user.role !== 'creator') return res.sendStatus(403);

  const photo = {
    id: uuid(),
    url: `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`,
    title: req.body.title,
    creator: req.user.name,
    reactions: { like: 0, love: 0, wow: 0, sad: 0 },
    comments: [],
    shares: 0
  };
  photos.unshift(photo);
  res.json(photo);
});

app.get('/api/photos', (req, res) => res.json(photos));

app.post('/api/photos/:id/react/:type', auth, (req, res) => {
  const p = photos.find(x => x.id === req.params.id);
  p.reactions[req.params.type]++;
  res.json(p.reactions);
});

app.post('/api/photos/:id/comment', auth, (req, res) => {
  const p = photos.find(x => x.id === req.params.id);
  p.comments.push({ user: req.user.name, text: req.body.text });
  res.json(p.comments);
});

app.post('/api/photos/:id/share', auth, (req, res) => {
  const p = photos.find(x => x.id === req.params.id);
  p.shares++;
  res.json({ shares: p.shares });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`SnapFlow running on port ${PORT}`));
