const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const {
    CognitoIdentityProviderClient,
    InitiateAuthCommand,
    SignUpCommand,
    ConfirmSignUpCommand,
    RespondToAuthChallengeCommand,
    GetUserCommand,
    ResendConfirmationCodeCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const multer = require('multer');
const fetch = require('node-fetch');
if (typeof global.fetch === 'undefined') {
    global.fetch = fetch;
}

const app = express();
const PORT = 3000;

const AWS_REGION = 'us-east-1';
const POOL_DATA = {
    UserPoolId: 'us-east-1_615K9TgMP',
    ClientId: '5vs8snp5sbpn6lj9g320klhleo',
};

const cognitoClient = new CognitoIdentityProviderClient({ region: AWS_REGION });
const s3Client = new S3Client({ region: AWS_REGION });
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'my-super-secret-key-please-change-me!',
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

const layout = (title, body, req) => `
  <h1><a href="/">Home</a></h1>
    ${req.session.cognitoAuthResult && req.session.cognitoAuthResult.AuthenticationResult ? '<a href="/logout">Logout</a>' : '<a href="/login">Login</a> <a href="/signup">Sign Up</a>'}
    <h2>${title}</h2>
${body}
`;

app.get('/', ensureAuthenticated, async (req, res) => {
    let subDisplay = 'N/A', emailDisplay = 'N/A', preferredUsernameDisplay = 'N/A';

    if (!req.session.userAttributes && req.session.cognitoAuthResult.AuthenticationResult.AccessToken) {
        try {
            const getUserCommand = new GetUserCommand({
                AccessToken: req.session.cognitoAuthResult.AuthenticationResult.AccessToken
            });
            const userData = await cognitoClient.send(getUserCommand);
            req.session.userAttributes = userData.UserAttributes;
            req.session.actualUsername = userData.Username;
        } catch (err) {
            console.error("Error fetching user attributes on home:", err);
        }
    }

    if (req.session.userAttributes) {
        const subAttr = req.session.userAttributes.find(attr => attr.Name === 'sub');
        const emailAttr = req.session.userAttributes.find(attr => attr.Name === 'email');
        const prefUserAttr = req.session.userAttributes.find(attr => attr.Name === 'preferred_username');
        if (subAttr) subDisplay = subAttr.Value;
        if (emailAttr) emailDisplay = emailAttr.Value;
        if (prefUserAttr) preferredUsernameDisplay = prefUserAttr.Value;
    }

    const body = `
        <h1>Welcome! You are successfully logged in.</h1>
        ${req.session.uploadSuccess ? `<p style="color: green;">${req.session.uploadSuccess}</p>` : ''}
        ${req.session.uploadError ? `<p style="color: red;">${req.session.uploadError}</p>` : ''}
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" />
            <input type="submit" value="Upload" />
        </form>
        <p>Canonical Username (sub): ${subDisplay}</p>
        <p>Email (alias): ${emailDisplay}</p>
        <p>Preferred Username (alias/username): ${preferredUsernameDisplay}</p>
    `;
    delete req.session.uploadSuccess;
    delete req.session.uploadError;
    res.send(layout('Home', body, req));
});

app.post('/upload', ensureAuthenticated, upload.single('file'), async (req, res) => {
    if (!req.file) {
        req.session.uploadError = 'No file uploaded.';
        return res.redirect('/');
    }

    const subAttr = req.session.userAttributes.find(attr => attr.Name === 'sub');
    const sub = subAttr ? subAttr.Value : null;
    if (!sub) {
        req.session.uploadError = 'User sub not found.';
        return res.redirect('/');
    }

    const params = {
        Bucket: 'your-s3-bucket-name', // Replace with your S3 bucket name
        Key: `${sub}/${req.file.originalname}`,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
    };

    try {
        const command = new PutObjectCommand(params);
        await s3Client.send(command);
        req.session.uploadSuccess = 'File uploaded successfully!';
    } catch (err) {
        console.error('Error uploading file:', err);
        req.session.uploadError = 'Error uploading file.';
    }

    res.redirect('/');
});

app.get('/login', (req, res) => {
    if (req.session.cognitoAuthResult && req.session.cognitoAuthResult.AuthenticationResult) return res.redirect('/');
    const error = req.session.loginError; delete req.session.loginError;
    const body = `${error ? `<p style="color: red;">${error}</p>` : ''}
        <form action="/login" method="post">
            <label>Email or Preferred Username:</label><br>
            <input type="text" name="identifier" /><br>
            <label>Password:</label><br>
            <input type="password" name="password" /><br>
            <input type="submit" value="Login" />
        </form>
        <p>Don't have an account? <a href="/signup">Sign Up</a></p>
    `;
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

app.get('/signup', (req, res) => {
    const error = req.session.signupError; const success = req.session.signupSuccess;
    delete req.session.signupError; delete req.session.signupSuccess;
    const body = `${error ? `<p style="color: red;">${error}</p>` : ''}${success ? `<p style="color: green;">${success}</p>` : ''}
        <form action="/signup" method="post">
            <label>Email (will be an alias):</label><br>
            <input type="email" name="email" /><br>
            <label>Preferred Username (this will be your main username):</label><br>
            <input type="text" name="preferred_username" /><br>
            <label>Password: (Min 8 chars, upper, lower, num, symbol)</label><br>
            <input type="password" name="password" /><br>
            <input type="submit" value="Sign Up" />
        </form>
        <p>Already have an account? <a href="/login">Login</a></p>
    `;
    res.send(layout('Sign Up', body, req));
});

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

app.get('/confirm', (req, res) => {
    const usernameForConfirmation = req.session.confirmUsername;
    if (!usernameForConfirmation) return res.redirect('/signup');
    const error = req.session.confirmError; delete req.session.confirmError;
    const body = `<p>A confirmation code was sent to your registered email. Please confirm account for username: ${usernameForConfirmation}.</p>
        ${error ? `<p style="color: red;">${error}</p>` : ''}
        <form action="/confirm" method="post">
            <label>Username (Preferred Username):</label><br>
            <input type="text" name="usernameToConfirm" value="${usernameForConfirmation}" /><br>
            <label>Confirmation Code:</label><br>
            <input type="text" name="code" /><br>
            <input type="submit" value="Confirm Account" />
        </form>
        <p><a href="/resend-code">Resend Code</a></p>
    `;
    res.send(layout('Confirm Account', body, req));
});

app.post('/confirm', async (req, res) => {
    const { usernameToConfirm, code } = req.body;
    if (!usernameToConfirm || !code) { req.session.confirmError = "Username and code are required."; return res.redirect('/confirm'); }

    const params = {
        ClientId: POOL_DATA.ClientId,
        Username: usernameToConfirm,
        ConfirmationCode: code,
    };

    try {
        const command = new ConfirmSignUpCommand(params);
        await cognitoClient.send(command);
        console.log('Confirmation successful for username:', usernameToConfirm);
        delete req.session.confirmUsername;
        const successBody = `<p>Account for ${usernameToConfirm} confirmed successfully!</p><p>You can now <a href="/login">login</a>.</p>`;
        res.send(layout('Confirmation Successful', successBody, req));
    } catch (err) {
        console.error("Confirmation error:", err);
        req.session.confirmError = err.message || JSON.stringify(err);
        res.redirect('/confirm');
    }
});

app.get('/resend-code', (req, res) => {
    const error = req.session.resendError; const success = req.session.resendSuccess;
    delete req.session.resendError; delete req.session.resendSuccess;
    const body = `${error ? `<p style="color: red;">${error}</p>` : ''} ${success ? `<p style="color: green;">${success}</p>` : ''}
        <form action="/resend-code" method="post">
            <label>Enter your Preferred Username:</label><br>
            <input type="text" name="usernameToResend" /><br>
            <input type="submit" value="Resend Code" />
        </form>
    `;
    res.send(layout('Resend Confirmation Code', body, req));
});

app.post('/resend-code', async (req, res) => {
    const { usernameToResend } = req.body;
    if (!usernameToResend) {
        req.session.resendError = "Preferred Username is required to resend code.";
        return res.redirect('/resend-code');
    }

    const params = {
        ClientId: POOL_DATA.ClientId,
        Username: usernameToResend,
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

app.get('/set-new-password', (req, res) => {
    if (!req.session.challengeInfo || req.session.challengeInfo.ChallengeName !== 'NEW_PASSWORD_REQUIRED') {
        return res.redirect('/login');
    }
    const error = req.session.newPasswordError; delete req.session.newPasswordError;
    const usernameForDisplay = req.session.challengeInfo.UsernameForChallenge;

    const body = `<p>A new password is required for your account (${usernameForDisplay}).</p>
        ${error ? `<p style="color: red;">${error}</p>` : ''}
        <form action="/set-new-password" method="post">
            <label>New Password:</label><br>
            <input type="password" name="newPassword" /><br>
            <label>Confirm New Password:</label><br>
            <input type="password" name="confirmPassword" /><br>
            <input type="submit" value="Set New Password" />
        </form>
    `;
    res.send(layout('Set New Password', body, req));
});

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

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error("Failed to destroy session during logout:", err);
        res.redirect('/login');
    });
});

app.get('/auth/cognito/callback', (req, res) => {
    const body = `<p>Auth Callback</p><p>This route is typically for OAuth flows.</p><p><a href="/login">Login</a></p>`;
    res.send(layout('Auth Callback', body, req));
});

app.listen(PORT, () => {
    console.log(`Node.js Cognito app server running on http://localhost:${PORT}`);
    console.log('------------------------------------------------------------------');
    console.log('IMPORTANT: Ensure POOL_DATA and S3 bucket name are configured correctly.');
    console.log('This version assumes your Cognito App Client has no secret.');
    console.log('Preferred Username is the primary username for sign-up.');
    console.log('------------------------------------------------------------------');
});
