//Base stuff frfr
const express = require('express');
const app = express();

//WebSocket
const WebSocket = require('ws');
const http = require('http').Server(app);
const wss = new WebSocket.Server({ server: http });

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

app.get('/chat', nameCheck, (req, res) => {
    const NAME = req.query.name;

    res.render('chat', { name: NAME });
});

app.get('/users', (req, res) => {
    res.json(userList(wss));
});