const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const jwtSecret = require('crypto').randomBytes(16);
const cookieParser = require('cookie-parser');
const JwtStrategy = require('passport-jwt').Strategy;
const argon2 = require('argon2'); // Import bcrypt
const db = require('./database'); // Import the database module
const axios = require('axios')
const { Issuer } = require('openid-client');
const radius = require('radius');
const dgram = require('dgram');
const dotenv = require('dotenv')
dotenv.config()

const app = express();
const port = 3000;

app.use(cookieParser());
app.use(logger('dev'));

passport.use('jwtCookie', new JwtStrategy(
    {
        jwtFromRequest: (req) => {
            if (req && req.cookies) { return req.cookies.jwt; }
            return null;
        },
        secretOrKey: jwtSecret
    },
    function (jwtPayload, done) {
        const { expiration, sub } = jwtPayload

        if (Date.now() > expiration) {
            done('Unauthorized', false)
        }
        
        console.log("Print: " + sub);

        done(null, jwtPayload)
        
        // if (jwtPayload.sub) {
        //     db.get('SELECT * FROM users WHERE username = ?', [jwtPayload.sub], (err, user) => {
        //         if (err) { return done(err); }
        //         if (!user) { return done(null, false); }
        //         // Add the examiner claim to the user object from the JWT payload
        //         console.log("JWTTTTTTTTT", jwtPayload.examiner)
        //         user.examiner = jwtPayload.examiner;
        //         return done(null, user);
        //     });
        // } else {
        //     return done(null, false);
        // }
    }
));

passport.use('username-password', new LocalStrategy(
    {
        usernameField: 'username',
        passwordField: 'password',
        session: false
    },
    function (username, password, done) {
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) { return done(err); }
            if (!user) { return done(null, false); }
            const passwordMatch = await argon2.verify(user.password, password);
            if (passwordMatch) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        });
    }
));

passport.use('local-radius', new LocalStrategy(
    {
        usernameField: 'username',
        passwordField: 'password',
        session: false
    },
    async function (username, password, done) {
        const secret = process.env.RADIUS_SECRET;
        const server = process.env.RADIUS_HOST;
        const packet = {
            code: 'Access-Request',
            secret: secret,
            identifier: 0,
            attributes: [
                ['NAS-IP-Address', '127.0.0.1'],
                ['User-Name', username],
                ['User-Password', password]
            ]
        };

        const encoded = radius.encode(packet);
        const client = dgram.createSocket('udp4');

        client.send(encoded, 0, encoded.length, 1812, server, (err) => {
            if (err) {
                client.close();
                return done(err);
            }
        });

        client.on('message', (msg) => {
            const response = radius.decode({ packet: msg, secret: secret });
            if (response.code === 'Access-Accept') {
                // Fetch additional user data from your database
                db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
                    if (err) {
                        return done(err);
                    }
                    if (!user) {
                        return done(null, false);
                    }
                    return done(null, user);
                });
            } else {
                return done(null, false);
            }
            client.close();
        });

        client.on('error', (err) => {
            client.close();
            return done(err);
        });
    }
));

app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

function checkExaminer(req, res, next) {
    console.log(req.user.examiner, req.user)
    if (req.user && req.user.examiner) {
        return next();
    } else {
        return res.status(403).send('Access denied. Examiner role required.');
    }
}

app.get('/',
    passport.authenticate(
        'jwtCookie',
        { session: false, failureRedirect: '/login' }
    ),
    (req, res) => {
        res.send(`Welcome to your private page, ${req.user.sub}`);
    }
);

app.get('/onlyexaminers',
    passport.authenticate(
        'jwtCookie',
        { session: false, failureRedirect: '/login' }
    ),
    checkExaminer,
    (req, res) => {
        res.send(`Hello examiner, ${req.user.sub}`);
    }
)

app.get('/login',
    (req, res) => {
        res.sendFile('login.html', { root: __dirname });
    }
);

app.post(
    '/login',
    passport.authenticate('local-radius', { failureRedirect: '/login', session: false }),
    (req, res) => {
        const isExaminer = req.user.username === 'alanis';

        const jwtClaims = {
            sub: req.user.username,
            iss: 'localhost:3000',
            aud: 'localhost:3000',
            exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
            role: 'user', // just to show a private JWT field
            examiner: isExaminer
        };
        const token = jwt.sign(jwtClaims, jwtSecret);

        res.cookie('jwt', token, { httpOnly: true, secure: true });
        res.redirect('/');

        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
    }
);

app.get('/logout', (req, res) => {
    res.clearCookie('jwt'); // Clear the JWT cookie
    res.redirect('/login'); // Redirect to the login page
});

// Endpoint to register a new user
app.get('/register', (req, res) => {
    res.sendFile('register.html', { root: __dirname });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await argon2.hash(password); // Hash the password

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
        if (err) {
            return res.status(500).send('Error registering new user.');
        }
        res.redirect('/login');
    });
});

app.use(function (err, req, res, next) {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});

app.get('/oauth2cb',

    async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
    /**
     * 1. Retrieve the authorization code from the query parameters
     */
    
  
    const code = req.query.code // Here we have the received code
    if (code === undefined) {
      const err = new Error('no code provided')
      err.status = 400 // Bad Request
      throw err
    }
  
    /**
     * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
     */
    const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
      client_id: "Ov23liq9bgWj4EuRaHJl",
      client_secret: "defc89dc0abcc5356d8b034f6d532802103990c7",
      code
    })
  
    console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.
  
    // Let us parse them ang get the access token and the scope
    const params = new URLSearchParams(tokenResponse.data)
    const accessToken = params.get('access_token')
    const scope = params.get('scope')
  
    // if the scope does not include what we wanted, authorization fails
    if (scope !== 'user:email') {
      const err = new Error('user did not consent to release email')
      err.status = 401 // Unauthorized
      throw err
    }

    /**
     * 3. Use the access token to retrieve the user email from the USER_API endpoint
     */
    const userDataResponse = await axios.get(process.env.USER_API, {
      headers: {
        Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
      }
    })
    const userEmail = userDataResponse.data.email;
    // isExaminer = userEmail === 'alanis'


    const jwtClaims = {
        sub: userEmail,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
        role: 'user',
    };

    const token = jwt.sign(jwtClaims, jwtSecret);

    res.cookie('jwt', token, { httpOnly: true, secure: true });
    res.redirect('/');

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
  })

  /// *******    OIDC
  /// *******    OIDC
  /// *******    OIDC
  /// *******    OIDC
  /// *******    OIDC
  /// *******    OIDC
  /// *******    OIDC
  /// *******    OIDC
  
  async function setupOIDC() {
    const oidcIssuer = await Issuer.discover(process.env.OIDC_ISSUER_URL);
    const client = new oidcIssuer.Client({
        client_id: process.env.OIDC_CLIENT_ID,
        client_secret: process.env.OIDC_CLIENT_SECRET,
        redirect_uris: [process.env.OIDC_REDIRECT_URI],
        response_types: ['code']
    });

    app.get('/auth/google', (req, res) => {
        const authorizationUrl = client.authorizationUrl({
            scope: 'openid email profile',
            response_type: 'code'
        });
        res.redirect(authorizationUrl);
    });

    app.get('/oidc/callback', async (req, res) => {
        try {
            const params = client.callbackParams(req);
            const tokenSet = await client.callback(process.env.OIDC_REDIRECT_URI, params);
            const userinfo = await client.userinfo(tokenSet.access_token);

            const jwtClaims = {
                sub: userinfo.email,
                iss: 'localhost:3000',
                aud: 'localhost:3000',
                exp: Math.floor(Date.now() / 1000) + 604800,
                role: 'user'
            };
            const token = jwt.sign(jwtClaims, jwtSecret);

            res.cookie('jwt', token, { httpOnly: true, secure: true });
            res.redirect('/');
            
            console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
            console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
        } catch (error) {
            console.error(error);
            res.status(500).send('Authentication failed');
        }
    });
}

setupOIDC();

//   async function setupOIDC() {
//     const oidcIssuer = await Issuer.discover(process.env.OIDC_ISSUER_URL);
//     const client = new oidcIssuer.Client({
//         client_id: process.env.OIDC_CLIENT_ID,
//         client_secret: process.env.OIDC_CLIENT_SECRET,
//         redirect_uris: [process.env.OIDC_REDIRECT_URI],
//         response_types: ['code']
//     });

//     passport.use('oidc', new OIDCStrategy({
//         client: client,
//         passReqToCallback: true,
//         params: {
//             scope: 'openid email profile'
//         }
//     }, (req, tokenset, userinfo, done) => {
//         isExaminer = userinfo.name === 'alanis'
        
//         const jwtClaims = {
//             sub: userinfo.email,
//             iss: 'localhost:3000',
//             aud: 'localhost:3000',
//             exp: Math.floor(Date.now() / 1000) + 604800,
//             role: 'user',
//             examiner: isExaminer
//         };
//         const token = jwt.sign(jwtClaims, jwtSecret);

//         req.res.cookie('jwt', token, { httpOnly: true, secure: true });

//         console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
//         console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
//         return done(null, userinfo);
//     }));

//     app.get('/auth/oidc', passport.authenticate('oidc'));

//     app.get('/oidc/callback', passport.authenticate('oidc', {
//         failureRedirect: '/login',
//         session: false
//     }), (req, res) => {
//         res.redirect('/');
//     });
// }

setupOIDC();
