//SO MUCH CONSTS
const express = require('express');
const app = express();
const path = require('path');
const { join } = require('path');
const sql = require('sqlite3');
const crypto = require('crypto');
const session = require('express-session');
const server = require('http').createServer(app);

const PORT = process.env.PORT || 3000;

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
    res.render(join('index'));
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/profile', isAuthed, (req, res) => {
    db.get('SELECT * FROM users WHERE username = ?', [req.session.user], (err, row) => {
        if (err) {
            res.send('An error occurred');
        } else {
            res.render('profile', { user: row });
        }
    });
});

app.post('/login', (req, res) => {
    if (req.body.username && req.body.password) {
        db.get('SELECT * FROM users WHERE username = ?; ', req.body.username, (err, row) => {
            if (err) res.render('/login', { message: 'An error occurred' });
            else if (!row) {
                const SALT = crypto.randomBytes(16).toString('hex');
                crypto.pbkdf2(req.body.password, SALT, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) res.redirect('/login');
                    else {
                        const hashPassword = derivedKey.toString('hex');
                        const joinDate = new Date().toISOString();
                        db.run('INSERT INTO users (username, password, salt, date) VALUES (?, ?, ?, ?);', [req.body.username, hashPassword, SALT, joinDate], (err) => {
                            if (err) res.send('An error occurred:\n' + err);
                            else {
                                res.redirect('/login');
                            }
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

    // Update all the ids and stuff frfr
    db.run('UPDATE posts SET poster_id = (SELECT uid FROM users WHERE username = ?), convo_id = (SELECT uid FROM convo WHERE uid = ?);', [req.body.username, req.body.convo_uid], (err) => {
        if (err) {
            console.log(err);
        } else {
            console.log('Updated post');
        }
    });
});

const db = new sql.Database('data/data.db', (err) => {
    if (err) {
        console.error(err);
    } else {
        console.log('Opened all tables');
    }
});

server.listen(PORT, () => {
    console.log(`Server started on port:${PORT}`);
});