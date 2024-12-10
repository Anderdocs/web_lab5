const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3000;

const db = mysql.createConnection({
    host: 'localhost',
    port: '3307',
    user: 'root',
    password: 'root',
    database: 'siteaboba',
});

db.connect(err => {
    if (err) {
        console.error('Database connection error:', err);
        process.exit(1);
    } else {
        console.log('Connected to MySQL database.');
    }
});

db.query(
    `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        plain_password VARCHAR(255)
    )`,
    err => err && console.error('Error creating table:', err)
);

db.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
     WHERE TABLE_NAME = 'users' AND COLUMN_NAME = 'plain_password'`,
    (err, results) => {
        if (!err && results.length === 0) {
            db.query(
                `ALTER TABLE users ADD COLUMN plain_password VARCHAR(255)`,
                err => err && console.error('Error adding column:', err)
            );
        }
    }
);

const adminPassword = bcrypt.hashSync('admin', 10);
db.query(
    `INSERT IGNORE INTO users (username, password, plain_password) VALUES ('admin', ?, 'admin')`,
    [adminPassword],
    err => err && console.error('Error inserting admin:', err)
);

app.use(bodyParser.json());
app.use(express.static('public'));

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || results.length === 0 || !bcrypt.compareSync(password, results[0].password)) {
            return res.status(401).send('Invalid credentials');
        }
        res.send({ message: 'Login successful', username: results[0].username });
    });
});

app.get('/api/users-with-passwords', (req, res) => {
    db.query('SELECT id, username, plain_password FROM users', (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.send(results);
    });
});

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    db.query(
        'INSERT INTO users (username, password, plain_password) VALUES (?, ?, ?)',
        [username, hash, password],
        err => {
            if (err) {
                const errorMsg = err.code === 'ER_DUP_ENTRY' ? 'Username already exists' : 'Error saving user';
                return res.status(400).send(errorMsg);
            }
            res.send({ message: 'User registered successfully' });
        }
    );
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));