//Base stuff frfr
const express = require('express');
const app = express();
const sqlite3 = require('sqlite3');
const crypto = require('crypto');
const session = require('express-session');
const path = require('path');
const jwt = require('jsonwebtoken');

//WebSocket
const WebSocket = require('ws');
const http = require('http').Server(app);
const wss = new WebSocket.Server({ server: http });

//Open database
const db = new sqlite3.Database('data/data.db', (err) => {
    if (err) {
        console.error('Database opening error: ', err);
    } else {
        console.log('Database opened');
    }
});

app.use(session({
    secret: 'LookAtMeImTheSecretNow',
    resave: false,
    saveUninitialized: false
}));

function isAuthenticated(req, res, next) {
    if (req.session.user) next()
    else res.redirect('/')
};

//Start thge srever
http.listen(3000, () => { console.log(`Server started on http://localhost:3000`); });

//EJS settings
app.set('view engine', 'ejs');

//Express settings
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//View folder frfr jon
app.set('views', __dirname + '/views');

//WebSocket connection
wss.on('connection', (ws) => {
    console.log(`New usser connected`);

    ws.on('message', (message) => {
        message = JSON.parse(String(message));

        if (message.hasOwnProperty('name')) {
            ws.name = message.name;
            broadcast(wss, { list: userList(wss).list });
        };

        if (message.hasOwnProperty('text')) {
            broadcast(wss, message);
        };
    });

    //When user leaves
    ws.on('close', () => {
        //This is the user that left
        broadcast(wss, { list: userList(wss).list });
    });
});


//FUNCTIONS
function broadcast(wss, message) {
    //console.log(`>>${message}<<`);
    for (let client of wss.clients) {
        client.send(JSON.stringify(message));
    };
};

function userList(wss) {
    const users = [];
    //console.log('0');
    wss.clients.forEach((client) => {
        //console.log('1');
        if (client.hasOwnProperty('name')) {
            users.push(client.name);
            //console.log(users);
            //console.log(`${client.name} Debug`);
        }
    });
    return { list: users };
};

function nameCheck(req, res, next) {
    let name = req.query.name;
    //console.log(name);
    if (name) {
        next();
    } else {
        res.redirect('/');
    };
};

//////////////////////////////////////
//////////////////////////////////////
//////////////////////////////////////
//////////////////////////////////////
//////////////////////////////////////

//App gets
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/pages', nameCheck, (req, res) => {
    const NAME = req.query.name;

    res.render('pages', { name: NAME });
});

app.get('/chat', nameCheck, isAuthenticated, (req, res) => {
    const NAME = req.query.name;

    res.render('chat', { name: NAME });
});

app.get('/help', nameCheck, isAuthenticated, (req, res) => {
    const NAME = req.query.name;

    res.render('help', { name: NAME });
});

app.post('/', (req, res) => {
    if (req.body.username && req.body.password) {
        db.get('SELECT * FROM users WHERE username = ?; ', req.body.username, (err, row) => {
            if (err) res.redirect('/', { message: 'An error occured' });
            else if (!row) {
                const SALT = crypto.randomBytes(16).toString('hex');
                crypto.pbkdf2(req.body.password, SALT, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) res.redirect('/');
                    else {
                        const hashPassword = derivedKey.toString('hex');
                        db.run('INSERT INTO users (username, password, salt) VALUES (?, ?, ?);', [req.body.username, hashPassword, SALT], (err) => {
                            if (err) res.send('An error occured:\n' + err);
                            else {
                                res.redirect('/');
                            };
                        });
                    }
                });
            } else {
                crypto.pbkdf2(req.body.password, row.salt, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) res.redirect('/');
                    else {
                        const hashPassword = derivedKey.toString('hex');
                        if (hashPassword === row.password) {
                            req.session.user = req.body.username;
                            res.redirect('/');
                        } else res.redirect('/');
                    }
                });
            }
        });
    }
});