const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');

dotenv.config();
const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(cors());

const USERS_FILE = path.join(__dirname, 'users.json');

// Функция для загрузки пользователей из файла
const loadUsers = () => {
    try {
        if (!fs.existsSync(USERS_FILE)) return [];
        const data = fs.readFileSync(USERS_FILE);
        return JSON.parse(data);
    } catch (err) {
        console.error('Error loading users:', err);
        return [];
    }
};

// Функция для сохранения пользователей в файл
const saveUsers = (users) => {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (err) {
        console.error('Error saving users:', err);
    }
};

// Загружаем пользователей при старте
let users = loadUsers();

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Регистрация
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: users.length + 1, username, password: hashedPassword };
    users.push(newUser);
    saveUsers(users); // Сохраняем в файл
    res.status(201).json({ message: 'User registered successfully' });
});

// Логин
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

// Middleware для проверки JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Защищённый маршрут
app.get('/protected', authenticateJWT, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});
