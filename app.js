const express = require('express');
const app = express();
const path = require('path');
const { join } = require('path');
const sql = require('sqlite3');
const session = require('express-session');
const crypto = require('crypto');
const http = require('http');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;

const server = http.createServer(app);
const io = new Server(server);

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use('/public', express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'LookAtMeImTheSecretNow',
    resave: false,
    saveUninitialized: false
}));

function isAuthed(req, res, next) {
    if (req.session.user) next();
    else res.redirect('/login');
}

app.get('/', isAuthed, (req, res) => {
    const name = req.session.user;

    res.render('index', { name });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/profile', isAuthed, (req, res) => {
    const name = req.session.user;
    res.render('profile', { name });
});

app.get('/chat', isAuthed, (req, res) => {
    const name = req.session.user;
    res.render('chat', { name });
});

app.get('/help', isAuthed, (req, res) => {
    const name = req.session.user;
    res.render('help', { name });
});

app.post('/login', (req, res) => {
    if (req.body.username && req.body.password) {
        db.get('SELECT * FROM users WHERE username = ?; ', req.body.username, (err, row) => {
            if (err) res.redirect('/login', { message: 'An error occured' });
            else if (!row) {
                const SALT = crypto.randomBytes(16).toString('hex');
                crypto.pbkdf2(req.body.password, SALT, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) res.redirect('/login');
                    else {
                        const hashPassword = derivedKey.toString('hex');
                        db.run('INSERT INTO users (username, password, salt) VALUES (?, ?, ?);', [req.body.username, hashPassword, SALT], (err) => {
                            if (err) res.send('An error occured:\n' + err);
                            else {
                                res.redirect('/login');
                            };
                        });
                    }
                });
            } else {
                crypto.pbkdf2(req.body.password, row.salt, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) res.redirect('/login');
                    else {
                        const hashPassword = derivedKey.toString('hex');
                        if (hashPassword === row.password) {
                            req.session.user = req.body.username;
                            res.redirect('/');
                        } else res.redirect('/login');
                    }
                });
            }
        });
    }
});

const db = new sql.Database('data/data.db', (err) => {
    if (err) {
        console.error(err);
    } else {
        console.log('Opened database');
    }
});

server.listen(PORT, () => {
    console.log(`Server started on port:${PORT}`);
});

//Socket.io
let userList = [];

io.on('connection', (socket) => {
    console.log(`User ${socket.id} connected.`);

    // Send all old messages to the new user
    db.all('SELECT * FROM posts', (err, rows) => {
        if (err) {
            console.log(err);
        } else {
            socket.emit('oldMessages', rows);
        }
    });

    socket.on('join', (data) => {
        userList.push(data.name);
        io.emit('message', { list: userList });
    });

    socket.on('data', (data) => {
        io.emit('message', { text: data });
    });

    socket.on('message', (data) => {
        io.emit('message', { name: data.name, text: data.text });
        db.run('INSERT INTO convo (title) VALUES (?);', [data.page], (err) => {
            if (err) console.log(err);
            else {
                console.log('Message added to database');
            }
        });
        db.run('INSERT INTO posts (poster, content, convo_id, time) VALUES (?,?,?,?)', [data.name, data.text, data.page, data.time], (err) => {
            if (err) console.log(err);
            else {
                console.log('Message added to database');
            }
        });
    });

    socket.on('disconnect', () => {
        console.log(`User ${socket.id} disconnected.`);
        // This is a bit of a wacky way to remove the user from the list, but it works.
        userList = userList.filter(user => user !== socket.id);
        io.emit('message', { list: userList });
    });
});