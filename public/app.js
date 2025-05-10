// Filename: app.js

const express = require('express');
const session = require('express-session');
const crypto = require('crypto'); // Kept for now, though computeSecretHash is removed. Can be removed if no other crypto needs.

// AWS SDK v3 for Cognito
const {
    CognitoIdentityProviderClient,
    InitiateAuthCommand,
    SignUpCommand,
    ConfirmSignUpCommand,
    RespondToAuthChallengeCommand,
    GetUserCommand, // To fetch user attributes after login
    ResendConfirmationCodeCommand // For resending confirmation code
} = require('@aws-sdk/client-cognito-identity-provider');

const fetch = require('node-fetch'); // Ensure global.fetch if any part needs it
if (typeof global.fetch === 'undefined') {
    global.fetch = fetch;
}

const app = express();
const PORT = 3000;

// --- START COGNITO CONFIGURATION ---
// TODO: Replace these values with your Terraform outputs / AWS Console values
const AWS_REGION = 'us-east-1'; // Same region as your Cognito User Pool
const POOL_DATA = {
    UserPoolId: 'us-east-1_615K9TgMP',     // Example: us-east-1_xxxxxxxxx
    ClientId: '5vs8snp5sbpn6lj9g320klhleo',   // Example: xxxxxxxxxxxxxxxxxxxxxxxxxx
    // ClientSecret is NOT USED in this version.
    // Ensure your Cognito App Client is configured WITHOUT a client secret.
};

const cognitoClient = new CognitoIdentityProviderClient({ region: AWS_REGION });
// --- END COGNITO CONFIGURATION ---

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'my-super-secret-key-please-change-me!', // TODO: Change this
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

function ensureAuthenticated(req, res, next) {
    if (req.session.cognitoAuthResult && req.session.cognitoAuthResult.AuthenticationResult) {
        return next();
    }
    res.redirect('/login');
}

// --- HTML TEMPLATES (Simplified) ---
const layout = (title, body, req) => `
  <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - Cognito App</title><style>body{font-family:Arial,sans-serif;margin:20px;background-color:#f4f4f4;color:#333}.container{background-color:#fff;padding:20px;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);max-width:500px;margin:auto}nav{margin-bottom:20px;text-align:center}nav a{margin:0 10px;text-decoration:none;color:#007bff}nav a:hover{text-decoration:underline}h1{color:#333;text-align:center}label{display:block;margin-bottom:5px;font-weight:bold}input[type="text"],input[type="email"],input[type="password"]{width:calc(100% - 22px);padding:10px;margin-bottom:15px;border:1px solid #ddd;border-radius:4px}button{background-color:#007bff;color:white;padding:10px 15px;border:none;border-radius:4px;cursor:pointer;font-size:16px}button:hover{background-color:#0056b3}.error{color:red;margin-bottom:15px;text-align:center}.success{color:green;margin-bottom:15px;text-align:center}.user-info{background-color:#e9ecef;padding:15px;border-radius:4px;margin-top:20px}.user-info p{margin:5px 0}</style></head>
  <body><div class="container"><nav><a href="/">Home</a>
    ${req.session.cognitoAuthResult && req.session.cognitoAuthResult.AuthenticationResult ? '<a href="/logout">Logout</a>' : '<a href="/login">Login</a> <a href="/signup">Sign Up</a>'}
    </nav><h1>${title}</h1>${body}</div></body></html>`;


// --- ROUTES ---

app.get('/', ensureAuthenticated, async (req, res) => {
    let emailDisplay = 'N/A', preferredUsernameDisplay = 'N/A', subDisplay = 'N/A';

    if (!req.session.userAttributes && req.session.cognitoAuthResult.AuthenticationResult.AccessToken) {
        try {
            const getUserCommand = new GetUserCommand({
                AccessToken: req.session.cognitoAuthResult.AuthenticationResult.AccessToken
            });
            const userData = await cognitoClient.send(getUserCommand);
            req.session.userAttributes = userData.UserAttributes;
            req.session.actualUsername = userData.Username; // Store the 'sub'
        } catch (err) {
            console.error("Error fetching user attributes on home:", err);
        }
    }
    
    subDisplay = req.session.actualUsername || 'N/A'; // Use the 'sub' if fetched

    if (req.session.userAttributes) {
        const emailAttr = req.session.userAttributes.find(attr => attr.Name === 'email');
        const prefUserAttr = req.session.userAttributes.find(attr => attr.Name === 'preferred_username');
        if (emailAttr) emailDisplay = emailAttr.Value;
        if (prefUserAttr) preferredUsernameDisplay = prefUserAttr.Value;
    }

    const body = `
        <p>Welcome! You are successfully logged in.</p>
        <div class="user-info">
            <p><strong>Canonical Username (sub):</strong> ${subDisplay}</p>
            <p><strong>Email (alias):</strong> ${emailDisplay}</p>
            <p><strong>Preferred Username (alias/username):</strong> ${preferredUsernameDisplay}</p>
        </div>
    `;
    res.send(layout('Home', body, req));
});

app.get('/login', (req, res) => {
    if (req.session.cognitoAuthResult && req.session.cognitoAuthResult.AuthenticationResult) return res.redirect('/');
    const error = req.session.loginError; delete req.session.loginError;
    const body = `${error ? `<p class="error">${error}</p>` : ''}
        <form method="POST" action="/login">
            <div><label for="identifier">Email or Preferred Username:</label><input type="text" id="identifier" name="identifier" required></div>
            <div><label for="password">Password:</label><input type="password" id="password" name="password" required></div>
            <button type="submit">Login</button>
        </form><p style="text-align:center; margin-top:15px;">Don't have an account? <a href="/signup">Sign Up</a></p>`;
    res.send(layout('Login', body, req));
});

app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;

    const params = {
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: POOL_DATA.ClientId,
        AuthParameters: {
            USERNAME: identifier,
            PASSWORD: password,
            // SECRET_HASH is not sent
        }
    };

    try {
        const command = new InitiateAuthCommand(params);
        const authResult = await cognitoClient.send(command);

        if (authResult.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
            req.session.challengeInfo = {
                ChallengeName: authResult.ChallengeName,
                Session: authResult.Session,
                UsernameForChallenge: identifier
            };
            return res.redirect('/set-new-password');
        }

        if (authResult.AuthenticationResult) {
            console.log('Authentication successful via USER_PASSWORD_AUTH!');
            req.session.cognitoAuthResult = authResult;
            
            try {
                const getUserCommand = new GetUserCommand({
                    AccessToken: authResult.AuthenticationResult.AccessToken
                });
                const userData = await cognitoClient.send(getUserCommand);
                req.session.userAttributes = userData.UserAttributes;
                req.session.actualUsername = userData.Username;
            } catch (getUserErr) {
                console.error("Error fetching user attributes post-login:", getUserErr);
                req.session.actualUsername = identifier;
            }

            req.session.save(err => {
                if (err) { console.error("Session save error:", err); req.session.loginError = "Session save error."; return res.redirect('/login'); }
                res.redirect('/');
            });
        } else {
            req.session.loginError = "Login failed: Unexpected response from Cognito.";
            res.redirect('/login');
        }
    } catch (err) {
        console.error('Authentication failed:', err);
        req.session.loginError = err.message || JSON.stringify(err);
        res.redirect('/login');
    }
});

// Sign Up page (GET)
app.get('/signup', (req, res) => {
    const error = req.session.signupError; const success = req.session.signupSuccess;
    delete req.session.signupError; delete req.session.signupSuccess;
    const body = `${error ? `<p class="error">${error}</p>` : ''}${success ? `<p class="success">${success}</p>` : ''}
        <form method="POST" action="/signup">
            <div><label for="email">Email (will be an alias):</label><input type="email" id="email" name="email" required></div>
            <div><label for="preferred_username">Preferred Username (this will be your main username):</label><input type="text" id="preferred_username" name="preferred_username" required></div>
            <div><label for="password">Password:</label><input type="password" id="password" name="password" required><em>(Min 8 chars, upper, lower, num, symbol)</em></div>
            <button type="submit">Sign Up</button>
        </form><p style="text-align:center; margin-top:15px;">Already have an account? <a href="/login">Login</a></p>`;
    res.send(layout('Sign Up', body, req));
});

// Sign Up action (POST)
app.post('/signup', async (req, res) => {
    const { email, password, preferred_username } = req.body;

    if (!preferred_username) {
        req.session.signupError = "Preferred Username is required.";
        return res.redirect('/signup');
    }
    const usernameForSignUp = preferred_username;
    const attributeList = [{ Name: 'email', Value: email }];

    const params = {
        ClientId: POOL_DATA.ClientId,
        Username: usernameForSignUp,
        Password: password,
        UserAttributes: attributeList,
        // SecretHash is not sent
    };

    try {
        const command = new SignUpCommand(params);
        const result = await cognitoClient.send(command);
        console.log('User registration initiated. Username:', usernameForSignUp, 'Sub:', result.UserSub);
        req.session.signupSuccess = `User registration initiated for ${usernameForSignUp}! A confirmation code has been sent to ${email}.`;
        req.session.confirmUsername = usernameForSignUp;
        res.redirect('/confirm');
    } catch (err) {
        console.error("Sign up error:", err);
        req.session.signupError = err.message || JSON.stringify(err);
        res.redirect('/signup');
    }
});

// Confirmation page (GET)
app.get('/confirm', (req, res) => {
    const usernameForConfirmation = req.session.confirmUsername;
    if (!usernameForConfirmation) return res.redirect('/signup');
    const error = req.session.confirmError; delete req.session.confirmError;
    const body = `<p>A confirmation code was sent to your registered email. Please confirm account for username: <strong>${usernameForConfirmation}</strong>.</p>${error ? `<p class="error">${error}</p>` : ''}
        <form method="POST" action="/confirm">
            <div><label for="usernameToConfirm">Username (Preferred Username):</label><input type="text" id="usernameToConfirm" name="usernameToConfirm" value="${usernameForConfirmation}" required readonly></div>
            <div><label for="code">Confirmation Code:</label><input type="text" id="code" name="code" required autofocus></div>
            <button type="submit">Confirm Account</button>
        </form><p style="text-align:center; margin-top:15px;"><a href="/resend-code">Resend Code</a></p>`;
    res.send(layout('Confirm Account', body, req));
});

// Confirmation action (POST)
app.post('/confirm', async (req, res) => {
    const { usernameToConfirm, code } = req.body;
    if (!usernameToConfirm || !code) { req.session.confirmError = "Username and code are required."; return res.redirect('/confirm'); }

    const params = {
        ClientId: POOL_DATA.ClientId,
        Username: usernameToConfirm,
        ConfirmationCode: code,
        // SecretHash is not sent
    };

    try {
        const command = new ConfirmSignUpCommand(params);
        await cognitoClient.send(command);
        console.log('Confirmation successful for username:', usernameToConfirm);
        delete req.session.confirmUsername;
        const successBody = `<p class="success">Account for ${usernameToConfirm} confirmed successfully!</p><p>You can now <a href="/login">login</a>.</p>`;
        res.send(layout('Confirmation Successful', successBody, req));
    } catch (err) {
        console.error("Confirmation error:", err);
        req.session.confirmError = err.message || JSON.stringify(err);
        res.redirect('/confirm');
    }
});

// Resend Confirmation Code page (GET)
app.get('/resend-code', (req, res) => {
    const error = req.session.resendError; const success = req.session.resendSuccess;
    delete req.session.resendError; delete req.session.resendSuccess;
    const body = `${error ? `<p class="error">${error}</p>` : ''} ${success ? `<p class="success">${success}</p>` : ''}
        <form method="POST" action="/resend-code">
            <div><label for="usernameToResend">Enter your Preferred Username:</label><input type="text" id="usernameToResend" name="usernameToResend" required></div>
            <button type="submit">Resend Code</button></form>`;
    res.send(layout('Resend Confirmation Code', body, req));
});

// Resend Confirmation Code action (POST)
app.post('/resend-code', async (req, res) => {
    const { usernameToResend } = req.body;
    if (!usernameToResend) {
        req.session.resendError = "Preferred Username is required to resend code.";
        return res.redirect('/resend-code');
    }

    const params = {
        ClientId: POOL_DATA.ClientId,
        Username: usernameToResend,
        // SecretHash is not sent
    };

    try {
        const command = new ResendConfirmationCodeCommand(params);
        await cognitoClient.send(command);
        console.log('Confirmation code resent successfully for username:', usernameToResend);
        req.session.resendSuccess = 'Confirmation code resent successfully. Please check your email.';
        req.session.confirmUsername = usernameToResend;
        res.redirect('/confirm');
    } catch (err) {
        console.error('Error resending confirmation code:', err);
        req.session.resendError = err.message || JSON.stringify(err);
        res.redirect('/resend-code');
    }
});

// Set New Password page (GET) - for NEW_PASSWORD_REQUIRED challenge
app.get('/set-new-password', (req, res) => {
    if (!req.session.challengeInfo || req.session.challengeInfo.ChallengeName !== 'NEW_PASSWORD_REQUIRED') {
        return res.redirect('/login');
    }
    const error = req.session.newPasswordError; delete req.session.newPasswordError;
    const usernameForDisplay = req.session.challengeInfo.UsernameForChallenge;

    const body = `<p>A new password is required for your account (${usernameForDisplay}).</p>${error ? `<p class="error">${error}</p>` : ''}
        <form method="POST" action="/set-new-password">
            <div><label for="newPassword">New Password:</label><input type="password" id="newPassword" name="newPassword" required></div>
            <div><label for="confirmPassword">Confirm New Password:</label><input type="password" id="confirmPassword" name="confirmPassword" required></div>
            <button type="submit">Set New Password</button></form>`;
    res.send(layout('Set New Password', body, req));
});

// Set New Password action (POST)
app.post('/set-new-password', async (req, res) => {
    if (!req.session.challengeInfo || req.session.challengeInfo.ChallengeName !== 'NEW_PASSWORD_REQUIRED') {
        return res.redirect('/login');
    }
    const { newPassword, confirmPassword } = req.body;
    const usernameForChallengeResponse = req.session.challengeInfo.UsernameForChallenge;
    const sessionFromChallenge = req.session.challengeInfo.Session;

    if (newPassword !== confirmPassword) {
        req.session.newPasswordError = "Passwords do not match."; return res.redirect('/set-new-password');
    }

    const params = {
        ChallengeName: 'NEW_PASSWORD_REQUIRED',
        ClientId: POOL_DATA.ClientId,
        ChallengeResponses: {
            USERNAME: usernameForChallengeResponse,
            NEW_PASSWORD: newPassword,
            // SECRET_HASH is not sent from ChallengeResponses
        },
        Session: sessionFromChallenge,
    };

    try {
        const command = new RespondToAuthChallengeCommand(params);
        const result = await cognitoClient.send(command);

        if (result.AuthenticationResult) {
            console.log('New password set and authenticated for:', usernameForChallengeResponse);
            delete req.session.challengeInfo;
            req.session.cognitoAuthResult = result;
            
            try {
                const getUserCommand = new GetUserCommand({ AccessToken: result.AuthenticationResult.AccessToken });
                const userData = await cognitoClient.send(getUserCommand);
                req.session.userAttributes = userData.UserAttributes;
                req.session.actualUsername = userData.Username;
            } catch (getUserErr) {
                console.error("Error fetching user attributes post-new-password:", getUserErr);
                req.session.actualUsername = usernameForChallengeResponse;
            }

            req.session.save(() => res.redirect('/'));
        } else {
            req.session.newPasswordError = "Failed to set new password. Unexpected response.";
            res.redirect('/set-new-password');
        }
    } catch (err) {
        console.error('Failed to set new password:', err);
        req.session.newPasswordError = err.message || JSON.stringify(err);
        res.redirect('/set-new-password');
    }
});

// Logout action (GET)
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error("Failed to destroy session during logout:", err);
        res.redirect('/login');
    });
});

app.get('/auth/cognito/callback', (req, res) => {
    const body = `<h2>Auth Callback</h2><p>This route is typically for OAuth flows.</p><a href="/login">Login</a>`;
    res.send(layout('Auth Callback', body, req));
});

app.listen(PORT, () => {
    console.log(`Node.js Cognito app server (NO SecretHash handling) running on http://localhost:${PORT}`);
    console.log('------------------------------------------------------------------');
    console.log('IMPORTANT: Ensure POOL_DATA in app.js is configured with your');
    console.log('Cognito User Pool ID and App Client ID from AWS.');
    console.log('This version ASSUMES YOUR COGNITO APP CLIENT HAS NO SECRET.');
    console.log('Preferred Username is THE PRIMARY USERNAME for sign-up.');
    console.log('------------------------------------------------------------------');
});
