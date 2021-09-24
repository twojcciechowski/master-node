const express = require('express');
const app = express();
const hostname = '127.0.0.1';
const port = 3000;
const cors = require('cors');
const fs = require('fs');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');
const dotenv = require("dotenv");
const {MongoClient} = require('mongodb');
const jwt = require("jsonwebtoken");
const methodOverride = require('method-override');


// get config vars
dotenv.config();

const url = `mongodb+srv://admin:${process.env.DB_ACCESS_PASWORD}@cluster0.onc04.mongodb.net/master?retryWrites=true&w=majority`;

app.use(express.json())
app.use(cors());
app.use(methodOverride('_method'));

app.get('/', (req, res) => {
    res.send('Hello World!');
})

app.get('/isalive', async (req, res) => {
    res.sendStatus(200);
})

app.get('/random-data', (req, res) => {
    fetch('https://randomuser.me/api/?results=200')
        .then(response => response.json())
        .then(async response => await Promise.all(response.results.map(async (item) => {
            item.login.hash = await bcrypt.hash(item.login.password, 10);
            return item;
        })))
        .then(async response => {
            const items = response.map(item => mapItem(item));
                await connectDB(async (client) => {
                    await client.db("master").collection("users").insertMany(items);
                });
            return response;
        })
        .then(response => fs.writeFile('users.json', JSON.stringify(response, null, 4), 'utf8', () => res.sendStatus(200)));
    })

// GET USER
app.get('/user/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    await connectDB(async (client) => {
        try {
            const { gender, name, email, login, phone, nat, location } = await client.db("master").collection("users").findOne({"login.uuid": id});
            const user = {
                personal: {
                    gender,
                    name,
                    email,
                    username: login.username,
                    phone,
                    nat,
                },
                location
            };
            res.status(200).send(user);
        } catch (e) {
            res.sendStatus(404);
        }
    });
});

// GET USERS
app.get('/users', authenticateToken, async (req, res) => {
    let { pageSize, page } = req.query;
    if (isNaN(pageSize)) {
        pageSize = 10;
    }
    if (isNaN(page)) {
        page = 1;
    }
    const pageNumber = Math.max(0, parseInt(page, 10));
    await connectDB(async (client) => {
        try {
            const users = await client
                .db("master")
                .collection("users")
                .find()
                .limit(parseInt(pageSize, 10))
                .skip(parseInt(pageSize, 10) * pageNumber)
                .toArray();
            res.status(200).send(users.map((user) => {
                return {
                    id: user.login.uuid,
                    username: user.login.username,
                };
            }));
        } catch (e) {
            console.log(e);
            res.sendStatus(404);
        }
    });
});

// CREATE USER
app.post('/user', async (req, res) => {
    const { body } = req;
    await connectDB(async (client) => {
        try {
            const { login, ...rest } = body;
            const { password, ...restLogin } = login;

            const hash = await bcrypt.hash(password, 10);
            await client.db("master").collection("users").insertOne({
                ...rest,
                login: {
                    ...restLogin,
                    hash
                }
            });
            res.sendStatus(200);
        } catch (e) {
            res.sendStatus(404);
        }
    });
});

// UPDATE USER
app.put('/user/:id', authenticateToken, async (req, res) => {
    const { body, params } = req;
    await connectDB(async (client) => {
        try {
            await client.db("master").collection("users").replaceOne(params.id, body);
            res.sendStatus(200);
        } catch (e) {
            res.sendStatus(404);
        }
    });
});

// DELETE USER
app.delete('/user/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    await connectDB(async (client) => {
        try {
            await client.db("master").collection("users").findOneAndDelete({"login.uuid": id});
            res.sendStatus(200);
        } catch (e) {
            res.sendStatus(400);
        }
    });
});

// MODIFY USER
app.patch('/user/me', authenticateToken, async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
        const username = getUserFromToken(token);
        if (username) {
            await connectDB(async (client) => {
                try {
                    const user = await client.db("master").collection("users").findOne({"email": username});
                    console.log(user);
                    res.sendStatus(200);
                } catch (e) {
                    res.status(404).send(e);
                }
            });
        } else {
            res.sendStatus(403);
        }

    } else {
        res.sendStatus(403);
    }
});

// POST LOGIN USER
app.post('/login', async (req, res) => {
    const { login, password } = req.body;
    await connectDB(async (client) => {
        try {
            const user = await client.db("master").collection("users").findOne({"email": login});
            const match = await bcrypt.compare(password, user.login.hash);
            if (match) {
                res.set({
                    'Authorization': `Bearer ${generateAccessToken({ username: login })}`,
                })
                res.sendStatus(200);
            } else {
                res.sendStatus(401);
            }
        } catch (e) {
            console.log(e);
            res.status(404).send(e);
        }
    });
});

app.listen(port, hostname, () => {
    console.log(`Example app listening at http://${hostname}:${port}`);
})

async function connectDB(callback) {
    const client = new MongoClient(url);

    try {
        await client.connect();
        await callback(client);
    } catch (e) {
        console.error('connect error:', e);
    } finally {
        console.log('close connection');
        await client.close();
    }
}

function authenticateToken(req, res, next) {
    // Gather the jwt access token from the request header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.sendStatus(401); // if there isn't any token
    }

    jwt.verify(token, `${process.env.ACCESS_TOKEN_SECRET}`, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next(); // pass the execution off to whatever request the client intended
    })
}

function generateAccessToken(username) {
    // expires after half and hour (1800 seconds = 30 minutes)
    return jwt.sign(username, `${process.env.ACCESS_TOKEN_SECRET}`, { expiresIn: '1800s' });
}

function getUserFromToken(token) {
    const decoded = jwt.decode(token, {complete: true});
    return decoded && decoded.payload && decoded.payload.username ? decoded.payload.username : null;
}

function mapItem(item) {
    return {
        email: item.email,
        gender: item.gender,
        name: item.name,
        location: {
            city: item.location.city,
            state: item.location.state,
            country: item.location.country,
            postcode: item.location.postcode,
            street: item.location.street,
        },
        login: {
            uuid: item.login.uuid,
            username: item.login.username,
            hash: item.login.hash,
        },
        phone: item.phone,
        nat: item.nat,
        picture: item.picture,
    }
}
