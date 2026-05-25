// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from root

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/../index.html');
});

mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/teamtodo')
  .then(() => console.log('✅ MongoDB Connected'));

// Models
const userSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'Member' }
});

const taskSchema = new mongoose.Schema({
  title: String,
  description: String,
  status: { type: String, default: 'Todo' },
  priority: { type: String, default: 'Medium' },
  category: { type: String, default: 'Work' },
  tags: [String],
  progress: { type: Number, default: 0 },
  dueDate: Date,
  createdBy: String,
  assignedTo: String
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Task = mongoose.model('Task', taskSchema);

// Auth Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    next();
  } catch {
    res.status(401).json({ msg: 'Invalid token' });
  }
};

// ===================== AUTH =====================
app.post('/api/register', async (req, res) => {
  try {
    const { name, username, email, password } = req.body;
    if (await User.findOne({ $or: [{ email }, { username }] })) {
      return res.status(400).json({ msg: 'User already exists (email or username)' });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, username, email, password: hashed });
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'secret123', { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, username: user.username, role: user.role, email: user.email } });
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier = email or username
    const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'secret123', { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, username: user.username, role: user.role, email: user.email } });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// ===================== ADMIN & STATS =====================
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, '-password');
    if (!user) return res.status(404).json({ msg: 'User not found' });
    res.json({ id: user._id, name: user.name, username: user.username, role: user.role, email: user.email });
  } catch (e) { res.status(500).json({ msg: 'Server error' }); }
});

app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).json({ msg: 'Forbidden' });
  const users = await User.find({}, '-password');
  res.json(users);
});

app.delete('/api/admin/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).json({ msg: 'Forbidden' });
  await User.findByIdAndDelete(req.params.id);
  res.json({ msg: 'User deleted' });
});

app.post('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).json({ msg: 'Forbidden' });
  try {
    const { name, username, email, password, role } = req.body;
    if (await User.findOne({ $or: [{ email }, { username }] })) {
      return res.status(400).json({ msg: 'User already exists (email or username taken)' });
    }
    const hashed = await bcrypt.hash(password || 'Password123', 10);
    const user = await User.create({ name, username, email, password: hashed, role: role || 'Member' });
    res.json({ id: user._id, name: user.name, username: user.username, role: user.role, email: user.email });
  } catch (err) { res.status(400).json({ msg: err.message }); }
});

app.get('/api/stats', auth, async (req, res) => {
  try {
    const stats = await Task.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    const formatted = stats.reduce((acc, curr) => ({ ...acc, [curr._id]: curr.count }), {});
    const recent = await Task.find().sort({ updatedAt: -1 }).limit(5).select('title status updatedAt');
    res.json({
      total: stats.reduce((a, b) => a + b.count, 0),
      todo: formatted.Todo || 0,
      inProgress: formatted['In Progress'] || 0,
      completed: formatted.Completed || 0,
      recent
    });
  } catch (e) { res.status(500).json({ msg: 'Server error' }); }
});

// ===================== TASKS =====================
app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await Task.find().sort({ createdAt: -1 });
  res.json(tasks);
});

app.post('/api/tasks', auth, async (req, res) => {
  const task = await Task.create({ ...req.body, createdBy: req.user.id });
  res.json(task);
  io.emit('taskCreated', task);
});

app.put('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ msg: 'Task not found' });
    const isOwner = req.user.role === 'Admin' || task.createdBy.toString() === req.user.id;
    // Non-owners can only update status and progress
    const updateData = isOwner ? req.body : { status: req.body.status, progress: req.body.progress };
    const updated = await Task.findByIdAndUpdate(req.params.id, updateData, { new: true });
    res.json(updated);
    io.emit('taskUpdated', updated);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ msg: 'Task not found' });
    if (req.user.role !== 'Admin' && task.createdBy !== req.user.id) {
      return res.status(403).json({ msg: 'Unauthorized' });
    }
    await Task.findByIdAndDelete(req.params.id);
    res.json({ msg: 'Deleted' });
    io.emit('taskDeleted', req.params.id);
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

module.exports = app;
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
}