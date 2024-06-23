// index.js
// Copyright 2024 Patrick Meade.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const { exec } = require('child_process');
const cookieParser = require('cookie-parser');
const express = require('express');
// const helmet = require('helmet')
const https = require('https');
const { request } = require('undici');
const util = require('util');
const { v4: uuidv4 } = require('uuid');

const { admins: ADMINS } = require("./admins.json")

const {
    BASE_URL, CLIENT_ID, CLIENT_SECRET, DISCORD_REDIRECT_URI,
    DISCORD_WEBHOOK_URL, DOCKER_CONTAINER_NAME, DOCKER_IMAGE_NAME, PORT,
    SS13_CONFIG_PATH, SS13_DATA_PATH, TLS_CERT, TLS_KEY, UPTIME_ROLE
} = process.env;

var lastDate = Date.now();
const sessionStore = {};


const app = express();
app.set('view engine', 'hbs');

app.use(cookieParser());
// app.use(helmet());
app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: true }));


// if they show up at the front door
app.get('/', (req, res, next) => {
    console.log(`${req.ip} is at the front door...`);

    // if they've got a cookie
    const sessionId = req.cookies.sessionId;
    if (sessionId && sessionStore[sessionId]) {
        // send them over to manage the server
        res.redirect('/server');
    } else {
        // otherwise, direct them to authenticate using Discord
        res.redirect('/login');
    }
});


// if they want to log out
app.get('/logout', (req, res, next) => {
    console.log(`${req.ip} is logging out.`);

    // if they've got a cookie
    const sessionId = req.cookies.sessionId;
    if (sessionId) {
        // if we've still got that information in the store
        if (sessionStore[sessionId]) {
            const { user } = sessionStore[sessionId];
            console.log(`Goodbye, ${user.global_name} (${user.id})`);
        }
        // forget about their cookie
        delete sessionStore[sessionId];
    }
    // tell them to forget about their cookie
    res.clearCookie('sessionId');
    // and if they want to come back, they better log in again
    res.redirect('/login');
});


// if the user wants to log in
app.get('/login', async (req, res) => {
    console.log(`${req.ip} would like to /login`);

    // show them the big friendly login button
    return res.render('login', {
        client_id: CLIENT_ID,
        redirect_uri: DISCORD_REDIRECT_URI
    });
});


// the user has hit the "Authorize" button with Discord
app.get('/auth', async (req, res) => {
    console.log(`${req.ip} is attempting to /auth`);

    // if we got a code from Discord
    const { code } = req.query;
    if (code) {
        try {
            // using the provided code, let's ask Discord for a token for this user
            const tokenResponseData = await request('https://discord.com/api/oauth2/token', {
                method: 'POST',
                body: new URLSearchParams({
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    code,
                    grant_type: 'authorization_code',
                    redirect_uri: DISCORD_REDIRECT_URI,
                    scope: 'identify',
                }).toString(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            });

            // parse the response that Discord gave us
            const oauthData = await tokenResponseData.body.json();
            console.log('Discord says:', oauthData);

            // if Discord says no about the token
            if (oauthData["error"] || tokenResponseData.statusCode == 401) {
                // send them back to the login screen to try again
                console.log('No token? NO /auth FOR YOU!'); // https://www.youtube.com/watch?v=zOpfsGrNvnk
                res.redirect('/login');
                return;
            }

            // otherwise, if we got an access token
            if (oauthData["access_token"]) {
                // great! let's ask for the user object (https://discord.com/developers/docs/resources/user#user-object)
                const userResult = await request('https://discord.com/api/users/@me', {
                    headers: {
                        authorization: `${oauthData.token_type} ${oauthData.access_token}`,
                    },
                });
                const user = await userResult.body.json();
                console.log('Discord says:', user);

                // if Discord won't give us the user object for some reason
                if (userResult.statusCode != 200) {
                    // send them back to the login screen to try again
                    console.log('No user object? NO /auth FOR YOU!'); // https://www.youtube.com/watch?v=zOpfsGrNvnk
                    res.redirect('/login');
                    return;
                }

                // But they were all of them deceived, for another Cookie was made.
                // In the land of Uptime, in the fires of Mount Node, the Dark Lord Blinkdog forged, in secret, a Master Cookie to control all others.
                // And into this Cookie he poured all his cruelty, his malice, and his will to dominate all life.
                // One Cookie to rule them all.
                const sessionId = uuidv4();
                res.cookie('sessionId', sessionId, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }); // 1 day
                // save that token to our session store
                sessionStore[sessionId] = {
                    oauthData,
                    user,
                };

                // send this newly authenticated user to server management
                res.redirect('/server');
                return;
            }
        } catch (error) {
            // NOTE: An unauthorized token will not throw an error
            // tokenResponseData.statusCode will be 401
            console.log('Something bad happened. NO /auth FOR YOU!'); // https://www.youtube.com/watch?v=zOpfsGrNvnk
            console.error(error);
        }
    }

    // oops, no code was provided; no deposit, no return buddy!
    // go back to the login screen and try again
    console.log('No code? NO /auth FOR YOU!'); // https://www.youtube.com/watch?v=zOpfsGrNvnk
    res.redirect('/login');
});


// check the authorization
const checkAuth = (req, res, next) => {
    console.log(`Checking authorization for ${req.ip}`);
    // if we have a session
    const sessionId = req.cookies.sessionId;
    if (sessionId && sessionStore[sessionId]) {
        // annotate the request with the user object
        const { user } = sessionStore[sessionId];
        req.user = user;
        // check our list of admins
        for (admin of ADMINS) {
            // if this user is on the list
            if (admin.id === user.id) {
                // this user is an admin too!
                req.user.isAdmin = true;
                req.admin = user;
                break;
            }
        }
        // call the next handler
        return next();
    }
    // this user is not authorized, send them back to /login
    res.redirect('/login');
};

// determine the status of everything, for display purposes
const computeServerStatus = async () => {
    // determine if the server is currently running
    const isRunning = await isDockerContainerRunning(DOCKER_CONTAINER_NAME);
    console.log("isRunning:", isRunning);

    // this captures the state of the server
    server = {
        defaultMessage: isRunning ? "Thank you for playing! See you next time!" : "Time to play STARFLY-13!",
        duration: getHumanReadableDuration(lastDate),
        status: isRunning ? "Up" : "Down",
        statusImageUrl: isRunning ? "img/server-up.webp" : "img/server-down.webp",
    };
    // return the status of the server to the caller
    return server;
};

// the user wants to see the status of the server
app.get('/server', checkAuth, async (req, res) => {
    // display the status of the server and admin controls (if authorized)
    res.render('server', {
        user: req.user,
        server: await computeServerStatus(),
    });
});


// the user wants to change the status of the server
app.post('/server', checkAuth, async (req, res) => {
    console.log(`${req.user.global_name} (${req.user.id}) is changing the server status`)

    // if this is an admin
    if (req.admin) {
        // process the form
        const adminMessage = req.body.adminMessage;
        const uptimeRole = req.body.uptimeRole === 'on';

        // log the received form data for debugging purposes
        console.log(`Admin message: ${adminMessage}`);
        console.log(`Uptime role checkbox is ${uptimeRole ? 'checked' : 'unchecked'}`);

        // determine if the server is running
        const isRunning = await isDockerContainerRunning(DOCKER_CONTAINER_NAME);
        // if the service container is running
        if (isRunning) {
            // stop the existing container
            await stopDockerContainer(DOCKER_CONTAINER_NAME);
        }
        // otherwise, since the service isn't running
        else {
            // pull the latest image
            await pullDockerImage(DOCKER_IMAGE_NAME);
            // start a new container
            await startDockerContainer(DOCKER_CONTAINER_NAME, DOCKER_IMAGE_NAME);
        }

        // update our uptime
        lastDate = Date.now();

        // send a message to Discord, if indicated
        await postToDiscordWebhook(req.user, adminMessage, uptimeRole);

        // send them back to see what they hath wrought
        return res.redirect('/server');
    }

    // naughty naughty
    console.log(`${req.user.global_name} (${req.user.id}) tried to hack Uptime`)
    return res.redirect('/server');
});


// start listening for incoming connections to the uptime service
const credentials = { cert: TLS_CERT, key: TLS_KEY };
const httpsServer = https.createServer(credentials, app);
httpsServer.listen(PORT, () => {
    console.log(`Uptime is running on ${BASE_URL}`);
});


//---------------------------------------------------------------------------------------------------------------------
// utility functions below...
//---------------------------------------------------------------------------------------------------------------------
const execAsync = util.promisify(exec);


// get the duration between the last event and now
function getHumanReadableDuration(lastEvent) {
    const now = Date.now();
    const duration = now - lastEvent;

    const seconds = Math.floor((duration / 1000) % 60);
    const minutes = Math.floor((duration / (1000 * 60)) % 60);
    const hours = Math.floor((duration / (1000 * 60 * 60)) % 24);
    const days = Math.floor(duration / (1000 * 60 * 60 * 24));

    let readableDuration = '';

    if (days > 0) {
        readableDuration += `${days} day${days !== 1 ? 's' : ''} `;
    }
    if (hours > 0) {
        readableDuration += `${hours} hour${hours !== 1 ? 's' : ''} `;
    }
    if (minutes > 0) {
        readableDuration += `${minutes} minute${minutes !== 1 ? 's' : ''} `;
    }
    if (seconds > 0 || readableDuration === '') {
        readableDuration += `${seconds} second${seconds !== 1 ? 's' : ''} `;
    }

    return readableDuration.trim();
}


// determine if the container is running
async function isDockerContainerRunning(containerName) {
    if (!containerName) {
        console.error('DOCKER_CONTAINER_NAME environment variable has not been set.');
        return false;
    }

    try {
        const { stdout, stderr } = await execAsync(`docker ps --filter "name=${containerName}" --filter "status=running" --format "{{.Names}}"`);
        if (stderr) {
            console.error(`Stderr: ${stderr}`);
        }
        if (stdout.trim() === containerName) {
            return true;
        }
    } catch (error) {
        console.error(`Error: ${error.message}`);
    }
    return false;
}


// send the uptime message (and possibly ping) to the discord webhook
async function postToDiscordWebhook(admin, message, uptimeRole) {
    // if the admin didn't provide any message to send, bail
    if (!message) {
        console.log('No message was provided. Nothing will be posted to Discord.');
        return;
    }
    // if the webhook isn't defined, bail
    if (!DISCORD_WEBHOOK_URL) {
        console.log('DISCORD_WEBHOOK_URL not defined in environment variables. Nothing will be posted to Discord.');
        return;
    }

    const content = uptimeRole ? `<@&${UPTIME_ROLE}> ${message}` : message;

    const payload = {
        username: admin.global_name,
        avatar_url: `https://cdn.discordapp.com/avatars/${admin.id}/${admin.avatar}.webp`,
        content: content
    };

    try {
        const { statusCode, body } = await request(DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (statusCode !== 204) {
            console.error('Error sending webhook:', await body.text());
        } else {
            console.log('Webhook sent successfully.');
        }
    } catch (error) {
        console.error('Error sending webhook:', error);
    }
}


// pull the latest image to run
async function pullDockerImage(imageName) {
    if (!imageName) {
        console.error('DOCKER_IMAGE_NAME environment variable has not been set.');
        return;
    }

    try {
        const { stdout, stderr } = await execAsync(`docker pull ${imageName}`);

        if (stderr) {
            console.error('Error pulling Docker image:', stderr);
            return;
        }

        console.log(`Docker image ${imageName} pulled successfully.`);
        console.log(stdout);
    } catch (error) {
        console.error('Error executing docker pull command:', error);
    }
}


// start a docker container for the service
async function startDockerContainer(containerName, imageName) {
    if (!containerName) {
        console.error('DOCKER_CONTAINER_NAME environment variable has not been set.');
        return;
    }
    if (!imageName) {
        console.error('DOCKER_IMAGE_NAME environment variable has not been set.');
        return;
    }

    const COMMAND = `docker run --detach --link starfly_db:starfly_db --name=${containerName} --publish 1337:1337 --rm --volume ${SS13_CONFIG_PATH}:/shiptest/config:ro --volume ${SS13_DATA_PATH}:/shiptest/data ${imageName}`;

    try {
        const { stdout, stderr } = await execAsync(COMMAND);

        if (stderr) {
            console.error('Error starting Docker container:', stderr);
            return;
        }

        console.log(`Docker container ${containerName} started successfully.`);
        console.log(stdout);
    } catch (error) {
        console.error('Error executing docker run command:', error);
    }
}


// stop the docker container that is currently running
async function stopDockerContainer(containerName) {
    if (!containerName) {
        console.error('DOCKER_CONTAINER_NAME environment variable has not been set.');
        return;
    }

    try {
        const { stdout, stderr } = await execAsync(`docker stop ${containerName}`);

        if (stderr) {
            console.error('Error stopping Docker container:', stderr);
            return;
        }

        console.log(`Docker container ${containerName} stopped successfully.`);
        console.log(stdout);
    } catch (error) {
        console.error('Error executing docker stop command:', error);
    }
}
