#!/usr/bin/env node

import mysql2 from 'mysql2';
import fs from 'fs'; 
import express from 'express';
import { engine } from 'express-handlebars';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import http from 'http';
import https from 'https';
import {
    pjclHex2BitArray,
    pjclBitArray2Hex,
    pjclHex2BigInt,
    pjclString2BitArray_UTF16BE,
    pjclSHA256,
    pjclRBG128Instantiate,
    pjclRBG128Reseed,
    pjclRBGGen,
    pjclHMAC_SHA256,
    pjclCurve_P256,
    pjclECDSAVerifyMsg
} from 'pjcl'; // in node_modules

import { SendEmailCommand } from "@aws-sdk/client-ses";
import { SESClient } from "@aws-sdk/client-ses";

// install_demo fixes the values of the following constants
//
const hostname = "HOSTNAME";
const senderAddress = "SENDERADDRESS";

const sesClient = new SESClient({ region: "us-east-1" });
const createSendEmailCommand = (toAddress, fromAddress, subject, body) => {
    return new SendEmailCommand({
	Destination: {ToAddresses: [toAddress]},
	Message: {
	    Body: {Html: {Charset: "UTF-8", Data: body}},
	    Subject: {Charset: "UTF-8", Data: subject}
	},
	Source: fromAddress
    });
};
const sendEmail = async (toAddress, fromAddress, subject, body) => {
    const sendEmailCommand = createSendEmailCommand(toAddress, fromAddress, subject, body);
    try {
	return await sesClient.send(sendEmailCommand);
    } catch (e) {
	console.error("Failed to send email:" + e);
	return e;
    }
};

/*
    computeEmailDerivedSeed(email, masterSecret) is computed as
    HKDF-Extract(salt, IKM), defined in RFC 5869 as HMAC-Hash(salt,
    IKM), with SHA-256 as the hash function, a string of 32 zero bytes as
    the salt, and the concatentation of email and masterSecret as the
    IKM
*/
function computeEmailDerivedSeed(email, masterSecret) {
    const salt_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    const salt_bits = pjclHex2BitArray(salt_hex);
    const email_bits = pjclString2BitArray_UTF16BE(email);
    const masterSecret_bits = pjclHex2BitArray(masterSecret);
    const IKM_bits = email_bits.concat(masterSecret_bits)

    // the following computes HKDF-Extract(salt, IKM) with SHA-256 as the hash function,
    // as defined in RFC 5869;
    // there is no need to use HKDF-Expand
    //
    const seed_bits = pjclHMAC_SHA256(salt_bits, IKM_bits);

    return seed_bits;
}

const rbgStateObject = new Object();
const rbgSecurityStrength = 128;
const reseedPeriod = 604093; // a little over 10 minutes

function getDevRandomBits(bitLength, f) {
    const byteLength = bitLength / 8;
    const buf = Buffer.alloc(byteLength); 
    (function fillBuf(bufPos) {
        let remaining = byteLength - bufPos;
        if (remaining == 0) {
            f(buf.toString('hex'));
            return;
        }
        fs.open('/dev/random', 'r', function(err, fd) {
            if (err) throw new Error(err);
            fs.read(fd, buf, bufPos, remaining, 0, function(err, bytesRead) {
                if (err) throw new Error(err);
                bufPos += bytesRead;
                fs.close(fd, function(err) {
                    if (err) throw new Error(err);
                    fillBuf(bufPos);
                });
            });
        });
    })(0);
}

function reseedPeriodically(period) {
    setTimeout(getDevRandomBits, period, rbgSecurityStrength, function(hex) {
        pjclRBG128Reseed(rbgStateObject, pjclHex2BitArray(hex));
        reseedPeriodically(period);
    });
}

let initializationComplete = false;
let currentMasterSecret;
let currentCSRFSecret;
const connection = mysql2.createConnection({socketPath: '/var/lib/mysql/mysql.sock'});

getDevRandomBits(rbgSecurityStrength, function(hex) {
    pjclRBG128Instantiate(rbgStateObject, pjclHex2BitArray(hex));
    reseedPeriodically(reseedPeriod);
    continue1();
});
function continue1 () {
    connection.query('CREATE DATABASE IF NOT EXISTS demo', function(err) {
	if (err) throw new Error(err);
	continue2();
    });
}
function continue2 (){
    connection.query('USE demo', function(err) {
	if (err) throw new Error(err);
	continue3();
    });
}
function continue3() {
    connection.query('CREATE TABLE IF NOT EXISTS users (' +
		     'email VARCHAR(255) NOT NULL, ' +
		     'firstname VARCHAR(255), ' +
		     'lastname VARCHAR(255), ' +
		     'masterSecretVersion VARCHAR(255), ' +
		     'fusionHash CHAR(64), ' +
		     'linkTimeStamp BIGINT, ' +
		     'emailVerifCodeHex CHAR(32), ' +
		     'challenge CHAR(32), ' +
		     'PRIMARY KEY (email)' +
		     ');', function(err) {
			 if (err) throw new Error(err);
			 continue4();
		     });
}
function continue4() {
    connection.query('CREATE TABLE IF NOT EXISTS sessions (' +
		     'sessionId VARCHAR(255) NOT NULL, ' +
		     'email VARCHAR(255) NOT NULL, ' +
		     'sessionTimeStamp BIGINT NOT NULL, ' +
		     'PRIMARY KEY (sessionId)' +
		     // sessionId is generated at random with high entropy 
		     // and should be probabilistically unique;
		     // something must be wrong if it isn't
		     ');', function(err) {
			 if (err) throw new Error(err);
			 continue5();
		     });
}
function continue5() {
    connection.query('CREATE TABLE IF NOT EXISTS masterSecretRotation (' +
		     'masterSecretVersion int NOT NULL AUTO_INCREMENT PRIMARY KEY, ' +
		     'masterSecret CHAR(64)' +
		     ');', function(err) {
			 if (err) throw new Error(err);
			 continue6();
		     });
}
function continue6() {
    const queryString = "SELECT masterSecretVersion from masterSecretRotation";
    const values = [];
    connection.query(queryString, values, function(err, results) {
	if (err) throw new Error(err);
        if (results.length == 0) {
	    const initialMasterSecret = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	    currentMasterSecret = initialMasterSecret;
	    const queryString = 'INSERT INTO masterSecretRotation (masterSecret) VALUES (?)';
	    const values = [initialMasterSecret];
	    connection.query(queryString, values, function(err) {
		if (err) throw new Error(err);
		continue7();
	    });
	}
	else {
	    continue7();
	}
    });
}
function continue7() {
connection.query('CREATE TABLE IF NOT EXISTS params (' +
		 'paramName VARCHAR(255), ' +
		 'paramValue VARCHAR(255) ' +
		 ');', function(err) {
		     if (err) throw new Error(err);
		     continue8();
		 });
}
function continue8() {
    const queryString = "SELECT paramValue from params where paramName = ?";
    const values = ["CSRFSecret"];
    connection.query(queryString, values, function(err, results) {
	if (err) throw new Error(err);
        if (results.length == 0) {
	    const initialCSRFSecret = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	    currentCSRFSecret = initialCSRFSecret;
	    const queryString = 'INSERT INTO params (paramName, paramValue) VALUES (?, ?)';
	    const values = ["CSRFSecret", initialCSRFSecret];
	    connection.query(queryString, values, function(err) {
		if (err) throw new Error(err);
		continue9();
	    });
	}
	else {
	    const result = results[0];
	    currentCSRFSecret = result.paramValue;
	    continue9();
	}
    });
}
function continue9() {
    connection.end();
    fs.copyFile("./node_modules/pjcl/pjcl.js", "./static/pjcl.js", function(err) {
	if (err) throw new Error(err);
	continue10();
    });
}
function continue10() {
    fs.copyFile("./node_modules/pjcl/browser-entropy.js", "./static/browser-entropy.js", function(err) {
	if (err) throw new Error(err);
	initializationComplete = true;
    });
}

function setCSRFCookie(res) {
    const CSRFSecretBits = pjclHex2BitArray(currentCSRFSecret);
    const randomBits = pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength);
    const signatureBits = pjclHMAC_SHA256(CSRFSecretBits, randomBits);
    const randomHex = pjclBitArray2Hex(randomBits);
    const signatureHex = pjclBitArray2Hex(signatureBits);
    const CSRFCookie = randomHex + "-" + signatureHex;
    res.cookie('CSRF', CSRFCookie, {secure: true});
}

function getVerifiedCSRFCookie(req) {
    const CSRFCookie = req.cookies.CSRF;
    if (!CSRFCookie) return null;
    const match = CSRFCookie.match(/[A-Fa-f0-9]+/g);
    if (!match || match.length != 2) return null;
    const randomHex = match[0];
    const signatureHex = match[1];
    const CSRFSecretBits = pjclHex2BitArray(currentCSRFSecret);
    const randomBits = pjclHex2BitArray(randomHex);
    const newSignatureBits = pjclHMAC_SHA256(CSRFSecretBits, randomBits);
    const newSignatureHex = pjclBitArray2Hex(newSignatureBits);
    if (signatureHex == newSignatureHex) {
	return CSRFCookie;
    }
    else {
	return null;
    }
}

const linkTimeout = 1800000; // 5 minutes
const sessionTimeout = 3600000; // 1 hour

const app = express();
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set('views', './views');

http.createServer(app).listen(80);
console.log("listening on port 80");

const tlsCertificate = fs.readFileSync("server-cert.pem");
const tlsPrivateKey = fs.readFileSync("server-key.pem");
const options = {
    cert: tlsCertificate,
    key: tlsPrivateKey
}
https.createServer(options, app).listen(443);
console.log("listening on port 443");

app.use(function(req,res,next) {
    if (!req.secure) {
        res.redirect(301,'https://' + req.headers.host + req.url);
    }
    else {
        next();
    }
});

app.use(function(req,res,next) {
    if (!initializationComplete) {
        res.status(503).send('SERVER BUSY, TRY AGAIN LATER');
    }
    else {
        next();
    }
});

// notifications and errors
//
app.get('/master-secret-rotated.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "The Master Secret has been rotated"
    });
});
app.get('/csrf-secret-rotated.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "The CSRF Secret has been rotated"
    });
});
app.get('/email-taken.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "Email taken"
    });
});
app.get('/input-validation-failure.html',function(req,res) {
    const errcode = req.query.errcode;
    res.render("error.handlebars", {
        msg: "Input validation failure",
        errcode: errcode
    });
});
app.get('/registration-failure.html',function(req,res) {
    const errcode = req.query.errcode;
    res.render("error.handlebars", {
        msg: "Registration failure",
        errcode: errcode
    });
});
app.get('/authentication-failure.html',function(req,res) {
    const errcode = req.query.errcode;
    res.render("error.handlebars", {
        msg: "Authentication failure",
        errcode: errcode
    });
});
app.get('/email-address-not-found.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "Email address not found"
    });
});
app.get('/link-expiration.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "The link you used has expired"
    });
});
app.get('/invalid-verification-code.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "Invalid verification code"
    });
});
app.get('/invalid-password.html',function(req,res) {
    res.render("notification.handlebars", {
        msg: "Invalid password"
    });
});
//
// end of notifications and errors

app.get('/rotateMasterSecret',function(req,res) {
    const currentMasterSecret = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    const queryString = 'INSERT INTO masterSecretRotation (masterSecret) VALUES (?)';
    const values = [currentMasterSecret];
    connection.query(queryString, values, function(err) {
	if (err) throw new Error(err);
    });
    res.redirect(303, '/master-secret-rotated.html');
});

app.get('/rotateCSRFSecret',function(req,res) {
    const currentCSRFSecret = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
    const queryString = 'UPDATE params SET paramValue = ? WHERE paramName = ? VALUES (?, ?)';
    const values = [currentCSRFSecret, "CSRFSecret"];
    connection.query(queryString, values, function(err) {
	if (err) throw new Error(err);
    });
    res.redirect(303, '/csrf-secret-rotated.html');
});

app.get('/',function(req,res) {
    res.redirect(303, "/public-page-1.html");
});

app.get('/register.html',function(req,res) {
    res.render("register.handlebars", {}); // => app.post('/register')
});

app.get('/please-log-in.html',function(req,res) {
    res.render("please-log-in.handlebars", {});
});

app.use(express.static('static'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// creates user record and sends install-credential-in-first-browser link
// no seed in link, only email verification code
//
app.post('/register',function(req,res) { 
    const email = req.body.email.toUpperCase();
    const firstname = req.body.firstname;
    const lastname = req.body.lastname;
    const CSRFToken = req.body.CSRFToken;
    const CSRFCookie = getVerifiedCSRFCookie(req);

    // input validation
    //
    if (
        email.search(/^[A-Z0-9]+@[A-Z0-9]+(\.[A-Z0-9]+)*\.[A-Z]+$/) == -1 ||
        firstname.search(/^[A-Za-z]+$/) == -1 ||
        lastname.search(/^[A-Za-z]+$/) == -1 ||
	!CSRFToken ||
        CSRFToken != CSRFCookie
    ) {
        res.redirect(303, "/input-validation-failure.html?errcode=1");
        return;
    };

    const linkTimeStamp = (new Date()).getTime();
    const emailVerifCodeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	"INSERT INTO users" +
	" (email, firstname, lastname, linkTimeStamp, emailVerifCodeHex)" +
        " VALUES (?, ?, ?, ?, ?)";
    const values = [email, firstname, lastname, linkTimeStamp, emailVerifCodeHex];
    connection.query(queryString, values, function(err) {
	if (err) {
	    res.redirect(303, "/email-taken.html");
	}
	else {
	    const subject = "Email verification and credential installation link";
	    const body =
		  `<p>
Open the link below in a browser to verify your email address and install the cryptographic credential:
</p>
<p>
<a href="https://${hostname}/install-credential-in-first-browser?email=${email}&emailVerifCodeHex=${emailVerifCodeHex}">Verify email address and install credential</a>
</p>`
	    sendEmail(email, senderAddress, subject, body);
	    res.render("message-sent-for-credential-installation-in-first-browser.handlebars", {
		senderAddress: senderAddress
	    });
	};
    });
});

//  response to user clicking on the install-credential-in-first-browser link
//
//  verifies email and checks that link has not timed out
//  retrieves the latest masterSecret and masterSecretVersion from the masterSecretRotation table
//  sets the masterSecretVersion in the user record
//  computes emailDerivedSeed
//  renders ask-for-password-and-register.handlebars
//
app.get('/install-credential-in-first-browser',function(req,res) {
    const email = req.query.email;
    const emailVerifCodeHex = req.query.emailVerifCodeHex;
    if (
        email.search(/^[A-Z0-9]+@[A-Z0-9]+(\.[A-Z0-9]+)*\.[A-Z]+$/) == -1 ||
        emailVerifCodeHex.search(/^[A-Fa-f0-9]+$/) == -1
    ) {
        res.redirect(303, "/input-validation-failure.html?errode=2"); // 
        return;
    }
    
    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });

    const queryString =
	  "SELECT linkTimeStamp, emailVerifCodeHex FROM users WHERE email=?";
    const values = [email];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            res.redirect(303, "/registration-failure.html?errcode=1");
            return;
        }
	const result = results[0];

	// consistency check
	//
	if (
	    !result.linkTimeStamp ||
            !result.emailVerifCodeHex
	) {
            res.redirect(303, "/registration-failure.html?errcode=2");
            return;
	}
	
	// link expiration check
	//
	const now = (new Date()).getTime();
	if (now - result.linkTimeStamp > linkTimeout) { 
            res.redirect(303, "/link-expiration.html");
            return;
	}
		     
	// verification code check
	//
	if (emailVerifCodeHex != result.emailVerifCodeHex) {
	    res.redirect(303, "/invalid-verification-code.html");
	    return;
	}

	const queryString =
	      "SELECT masterSecret, masterSecretVersion FROM masterSecretRotation ORDER BY masterSecretVersion DESC LIMIT 1";
	connection.query(queryString, [], function(err, results) {
            if (err) throw new Error(err);
            if (results.length == 0) {
		res.redirect(303, "/registration-failure.html?errcode=2");
		return;
            }
	    const result = results[0];
	    const masterSecretVersion = result.masterSecretVersion;

	    const queryString =
		  "UPDATE users SET masterSecretVersion = ? WHERE email = ?";
	    const values = [masterSecretVersion, email];
	    connection.query(queryString, values, function(err, results) {
		if (err) throw new Error(err);
	    });

	    const emailDerivedSeed = computeEmailDerivedSeed(email, result.masterSecret);

	    // prompts for password + confirmation,
	    // constructs cryptographic credential from emailDerivedSeed
	    // computes fusion hash
	    // 
	    res.render("ask-for-password-and-install-credential.handlebars", { // => app.post('/finalize-registration')
		email: email,
		emailVerifCodeHex: emailVerifCodeHex,
		emailDerivedSeed: emailDerivedSeed
	    });
	});
    });
});

// registers the fusion hash
//
app.post('/finalize-registration',function(req,res) {
    const email = req.body.email;
    const emailVerifCodeHex = req.body.emailVerifCodeHex;
    const fusionHash = req.body.fusionHash;
    const CSRFToken = req.body.CSRFToken;
    const CSRFCookie = getVerifiedCSRFCookie(req);

    // input validation
    //
    if (
        email.search(/^[A-Z0-9]+@[A-Z0-9]+(\.[A-Z0-9]+)*\.[A-Z]+$/) == -1 ||
        emailVerifCodeHex.search(/^[A-Fa-f0-9]+$/) == -1 ||
        fusionHash.search(/^[A-Fa-f0-9]+$/) == -1 ||
        !CSRFToken ||	    
        CSRFToken != CSRFCookie
    ) {
        res.redirect(303, "/input-validation-failure.html?errcode=3"); // 
        return;
    }

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString = "UPDATE users SET fusionHash = ? WHERE email = ? AND emailVerifCodeHex = ?"
    const values = [fusionHash, email, emailVerifCodeHex];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            res.redirect(303, "/registration-failure.html?errcode=3");
            return;
        }
	// login session creation
	//
	const connection = mysql2.createConnection({
	    socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "INSERT INTO sessions (sessionId, email, sessionTimeStamp) VALUES (?, ?, ?)";
	const sessionId = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	const sessionTimeStamp = new Date().getTime();
	const values = [sessionId, email, sessionTimeStamp];
	connection.query(queryString, values, function (err) {
	    if (err) throw new Error(err);
	    res.cookie('session', sessionId, {httpOnly: true, secure: true});
	    res.redirect(303, "/private-page-1.html");
	});
    });
});

// partials/pagetop-login-form.handlebars and
// partials/please-log-in.handlebars
// =>
// app.post('/log-in')

app.post('/log-in',function(req,res) { 
    const email = req.body.email.toUpperCase();
    const credentialFound = req.body.credentialFound;
    const CSRFToken = req.body.CSRFToken;
    const CSRFCookie = getVerifiedCSRFCookie(req);

    // input validation
    //
    if (
        email.search(/^[A-Z0-9]+@[A-Z0-9]+(\.[A-Z0-9]+)*\.[A-Z]+$/) == -1 ||
        !(credentialFound == "yes" || credentialFound == "no") ||
        !CSRFToken ||	    
        CSRFToken != CSRFCookie
    ) {
        res.redirect(303, "/input-validation-failure.html?errcode=4");
        return;
    }

    if (credentialFound == "yes") {
	// generate server entropy for signature
	// generate and record challenge
	// render authenticate-with-existing-credential.handlebars, passing the server entropy and the challenge
	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "UPDATE users SET challenge = ? WHERE email = ?";
	const challengeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	const values = [challengeHex, email];
	connection.query(queryString, values, function(err, results) {
            if (err) throw new Error(err);
            if (results.affectedRows == 0) {
		res.redirect(303, "/email-address-not-found.html");
		return;
            }
	    
	    const serverEntropyHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	    
	    // prompt for password
            // sign challenge
	    // compute secretSaltedPassword
	    // submit email and authnData: public key, signature, secretSaltedPassword, 
	    // 
            res.render("authenticate-with-existing-credential.handlebars", { // => app.post('/finalize-authentication')
		email: email,
		serverEntropyHex: serverEntropyHex,
		challengeHex: challengeHex
            });
	});
    }
    else {
	// generate and set email verification code
	// set linkTimeStamp
	// send link
	// render message-sent-for-credential-installation-in-new-browser,
	// which says that the credential was not found
	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "UPDATE users SET linkTimeStamp = ?, emailVerifCodeHex = ? WHERE email = ?";
	const linkTimeStamp = new Date().getTime();
	const emailVerifCodeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	const values = [linkTimeStamp, emailVerifCodeHex, email]; 
	connection.query(queryString, values, function(err, results) {
            if (err) throw new Error(err);
            if (results.affectedRows == 0) {
		res.redirect(303, "/email-address-not-found.html");
            }
	    else {
		const subject = "Email verification and credential installation link";
		const body =
		      `<p>
Open the link below in a browser to verify your email address, install
the cryptographic credential for your email address in the browser, and log in.  
</p>
<p>
<a href="https://${hostname}/install-credential-in-new-browser?email=${email}&emailVerifCodeHex=${emailVerifCodeHex}">Verify email address and install credential</a>
</p>`
		sendEmail(email, senderAddress, subject, body);
		res.render("message-sent-for-credential-installation-in-new-browser.handlebars", { 
		    senderAddress: senderAddress
		});
	    }
	});
    }
});

app.post('/finalize-authentication',function(req,res) {
    const email = req.body.email;
    const pubKeyHex_Q_x = req.body.pubKeyHex_Q_x;
    const pubKeyHex_Q_y = req.body.pubKeyHex_Q_y;
    const sigHex_r = req.body.sigHex_r;
    const sigHex_s = req.body.sigHex_s;
    const secretSaltedPasswordHex = req.body.secretSaltedPasswordHex;
    const CSRFToken = req.body.CSRFToken;
    const CSRFCookie = getVerifiedCSRFCookie(req);

    // input validation
    //
    if (
        email.search(/^[A-Z0-9]+@[A-Z0-9]+(\.[A-Z0-9]+)*\.[A-Z]+$/) == -1 ||
        pubKeyHex_Q_x.search(/^[A-Fa-f0-9]+$/) == -1 ||
        pubKeyHex_Q_y.search(/^[A-Fa-f0-9]+$/) == -1 ||
        sigHex_r.search(/^[A-Fa-f0-9]+$/) == -1 ||
        sigHex_s.search(/^[A-Fa-f0-9]+$/) == -1 ||
	secretSaltedPasswordHex.search(/^[A-Fa-f0-9]+$/) == -1 ||
        !CSRFToken ||
        CSRFToken != CSRFCookie
    ) {
        res.redirect(303, "/input-validation-failure.html?errcode=5"); // 
        return;
    }

    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	"SELECT challenge, fusionHash FROM users WHERE email=?";
    const values = [email];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            // the credential was found by the browser, so something is wrong
            res.redirect(303, "/authentication-failure.html?errcode=1");
            return;
        }
        const result = results[0];
        const challengeHex = result.challenge;
        if (!challengeHex) {
            res.redirect(303, "/authentication-failure.html?errcode=2");
            return;
        }
        const fusionHashHex_in_database = result.fusionHash;
        if (!fusionHashHex_in_database) {
            res.redirect(303, "/authentication-failure.html?errcode=3");
            return;
        }
	
        // verification of the authentication signature
        //
        const x = pjclHex2BigInt(pubKeyHex_Q_x);
        const y = pjclHex2BigInt(pubKeyHex_Q_y);
        const Q = {x:x, y:y, z:[1]};
        const r = pjclHex2BigInt(sigHex_r);
        const s = pjclHex2BigInt(sigHex_s);
        const challengeBitArray = pjclHex2BitArray(challengeHex);
        if (!pjclECDSAVerifyMsg(pjclCurve_P256, Q, challengeBitArray, r, s)) {
	    res.redirect(303, "/authentication-failure.html?errcode=3");
	    return;
        }

        // verification of the fusion hash
	
	const pubKeyBits = pjclHex2BitArray(pubKeyHex_Q_x + pubKeyHex_Q_y);
	const secretSaltedPassword = pjclHex2BitArray(secretSaltedPasswordHex);
	const fusionHashBits = pjclSHA256(secretSaltedPassword,pubKeyBits);
        if (pjclBitArray2Hex(fusionHashBits) != fusionHashHex_in_database) {
	    res.redirect(303, "/invalid-password.html");
	    return;
        }

	// login session creation
	//
	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "INSERT INTO sessions (sessionId, email, sessionTimeStamp) VALUES (?, ?, ?)";
	const sessionId = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	const sessionTimeStamp = new Date().getTime();
	const values = [sessionId, email, sessionTimeStamp];
	connection.query(queryString, values, function (err) {
            if (err) throw new Error(err);
	    res.cookie('session', sessionId, {httpOnly: true, secure: true});
	    res.redirect(303, `/private-page-1.html`);
	});
    });
});

//  response to user clicking on the install-credential-in-new-browser link

//  verifies email and checks that link has not timed out
//  computes emailDerivedSeed
//  renders install-credential-and-authenticate
//
app.get('/install-credential-in-new-browser',function(req,res) {
    const email = req.query.email;
    const emailVerifCodeHex = req.query.emailVerifCodeHex;

    // input validation
    //
    if (
        email.search(/^[A-Z0-9]+@[A-Z0-9]+(\.[A-Z0-9]+)*\.[A-Z]+$/) == -1 ||
        emailVerifCodeHex.search(/^[A-Fa-f0-9]+$/) == -1
    ) {
        res.redirect(303, "/input-validation-failure.html?errcode=6");
        return;
    }
    
    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	  "SELECT " +
	  "u.linkTimeStamp as linkTimeStamp, " +
          "u.emailVerifCodeHex as emailVerifCodeHex, " +
          "m.masterSecret as masterSecret " +
	  "FROM " +
	  "users u INNER JOIN masterSecretRotation m " +
	  "ON u.masterSecretVersion = m.masterSecretVersion " +
	  "WHERE email=?";
    const values = [email];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            res.redirect(303, "/authentication-failure.html?errcode=1");
            return;
        }
	const result = results[0];

	// consistency check
	//
	if (
	    !result.linkTimeStamp ||
            !result.emailVerifCodeHex
	) {
            res.redirect(303, "/authentication-failure.html?errcode=3");
            return;
	}
	
	// link expiration check
	//
	const now = (new Date()).getTime();
	if (now - result.linkTimeStamp > linkTimeout) { 
            res.redirect(303, "/link-expiration.html");
            return;
	}
	
	// verification code check
	//
	if (emailVerifCodeHex != result.emailVerifCodeHex) {
	    res.redirect(303, "/invalid-verification-code.html");
	    return;
	}

	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "UPDATE users SET challenge = ? WHERE email = ?";
	const challengeHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));
	const values = [challengeHex, email];
	connection.query(queryString, values, function(err, results) {
            if (err) throw new Error(err);
            if (results.affectedRows == 0) {
		res.redirect(303, "/email-address-not-found.html");
		return;
            }

	    const emailDerivedSeed = computeEmailDerivedSeed(email, result.masterSecret);
	    const serverEntropyHex = pjclBitArray2Hex(pjclRBGGen(rbgStateObject,rbgSecurityStrength,rbgSecurityStrength));

            if (!getVerifiedCSRFCookie(req)) {
                setCSRFCookie(res);
            }
	    // prompt for password,
	    // construct cryptographic credential from seed
            // sign challenge
	    // compute secretSaltedPassword
	    // submit public key, signature, secretSaltedPassword, 
	    // 
            res.render("install-credential-and-authenticate.handlebars", { // => app.post('finalize-authentication')
		email: email,
		emailDerivedSeed: emailDerivedSeed,
		serverEntropyHex: serverEntropyHex, 
		challengeHex: challengeHex
            });
	});
    });
});
	 
app.get('/logout',function(req,res) {
    const sessionId = req.cookies.session;
    if (sessionId) {
        res.clearCookie('session');

	const connection = mysql2.createConnection({
            socketPath: '/var/lib/mysql/mysql.sock',
	    database: 'demo'
	});
	const queryString = "DELETE FROM sessions WHERE sessionId = ?";
	const values = [sessionId];
	connection.query(queryString, values, function(err) {
            if (err) throw new Error(err);
            res.redirect(303, "/public-page-1.html");
        });
    }
    else {
        res.redirect(303, "/public-page-1.html");
    }
});

function checkIfLoggedIn(req,res,next) {
    const sessionId = req.cookies.session;
    if (
        !sessionId ||
        sessionId.search(/^[A-Fa-f0-9]+$/) == -1
    ) {
        res.locals.loggedIn = false;
        next();
        return;
    }   
    const connection = mysql2.createConnection({
        socketPath: '/var/lib/mysql/mysql.sock',
	database: 'demo'
    });
    const queryString =
	"SELECT u.email AS email, u.firstname AS firstname, u.lastname AS lastname FROM " +
	"users u INNER JOIN sessions s " +
	"ON u.email = s.email " +
	"WHERE s.sessionId = ? " +
	"AND ? - s.sessionTimeStamp < ?";
    const now = (new Date()).getTime();
    const values = [sessionId, now, sessionTimeout];
    connection.query(queryString, values, function(err, results) {
        if (err) throw new Error(err);
        if (results.length == 0) {
            res.locals.loggedIn = false;
            next();
        }
	else {
	    const result = results[0];
            res.locals.loggedIn = true;
            res.locals.email = result.email;
            res.locals.fullName = `${result.firstname} ${result.lastname}`;
            next();
	}
    });
}

app.use(checkIfLoggedIn);

const publicPageNames = [
    "public-page-1",
    "public-page-2",
    "public-page-3"
];
publicPageNames.forEach(function(pageName) {
    app.get(`/${pageName}.html`,function(req,res) {
	if (!getVerifiedCSRFCookie(req)) {
	    setCSRFCookie(res);
	}
        res.render(`${pageName}.handlebars`);
    });
});
const privatePageNames = [
    "private-page-1",
    "private-page-2",
    "private-page-3"
];
privatePageNames.forEach(function(pageName) {
    app.get(`/${pageName}.html`,function(req,res) {
	if (!getVerifiedCSRFCookie(req)) {
	    setCSRFCookie(res);
	}
        if (res.locals.loggedIn) {
            res.render(`${pageName}.handlebars`);
        }
        else {
            res.redirect(303,`/please-log-in.html?destination=${pageName}`);
        }
    });
});

app.use(function(req,res) {
    res.status(404).send('NOT FOUND');
});
app.use(function(err,req,res,next) {
    console.log("Error: " + err.stack);
    res.status(500).send('INTERNAL ERROR');
});
