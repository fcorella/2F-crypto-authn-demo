# A Demonstration of Two-Factor Cryptographic Authentication with a Familiar User Experience

As announced and in this [blog
post](/2023/08/07/a-demonstration-of-two-factor-cryptographic-authentication-with-a-familiar-user-experience/),
this repository contains the code of a demonstration of two-factor
cryptographic authentication of a user to a web site (the relying
party, RP), using a [fusion
credential](/cryptographic-authentication/#fusion) that combines a
password with an extended key-pair to provide strong security and a
familiar user experience.

## Live demo

A live demonstration of the code is available at `demo.pomcor.com`.
The live demo may be discontinued or restarted at any time; but if you
have an AWS account that allows you to send mail, you can set up and
run the demo on your own EC2 instance, using the install-script
included in the repository, following instructions that you can find
below.

## User experience

### Registration

1. The user visits the registration page in a browser and enters user
data (first and last name in this demo) and an email address.

1. An email verification link is sent to the address.

1. The user opens the link in the browser; the address is verified, a
cryptographic credential is installed, and the user is asked to choose
a password.

1. The user enters and confirms the password.

1. The registration is completed, and the user is logged in on the browser.

### Login on a browser where a cryptographic credential has been
installed

1. The user submits her email address and is prompted for her
password.

1. The user submits her password.

1. The user is authenticated and logged in on the browser.

### Login on a browser where there is no cryptographic credential

1. The user submits her email address.

1. An email verification link is sent to the address.

1. The user opens the link in the browser; the address is verified, a
cryptographic credential is installed, and the user is prompted for
her password.

1. The user submits her password.

1. The user is authenticated and logged in on the browser.

## Authentication protocol

### At registration, the JavaScript frontend of the RP:

1. Generates a cryptographic credential consisting of a key pair extended with a secret salt.

1. Hashes the user's password with the secret salt.

1. Hashes the salted password with the public key, obtaining a "fusion hash".

1. Registers the fusion hash with the backend.

### To authenticate:

1. The backend sends a challenge.

1. The frontend asks the user for the password and hashes it with the
secret salt.

1. The frontend signs the challenge with the private key.

1. The frontend sends the signature, the salted password, and the
public key to the backend.

1. The backend verifies the signature.

1. The backend computes the fusion hash from the salted password and
the public key, and verifies it against the registered fusion hash.

1. The backend deletes the salted password and the public key that it
has received from the frontend.

## Replication of the cryptographic credential across all browsers in all devices

The same extended key pair is used in all browsers and devices.  This
is achieved without credential synchronization by:

  * Deriving a seed for the generation of pseudo-random bits from the
    email address and a master secret.
    
  * Using pseudo-random bits derived from the seed in the generation of
    the cryptographic credential, upon email verification.

## Code details

### CSRF protection

Forms are protected against cross-site request forgery (CSRF) using
the [Signed Double Submit pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#signed-double-submit-cookie).

### Rotation of the master secret

The master secret can be rotated to allow a user to continue using the
same email address after the credential derived from the address has
been compromised.  This is implemented using a database table of
master record versions where each record contains an auto-incremented
version number and a corresponding random value of the master record.
When a user registers, the latest version number is stored in the user
record, causing the corresponding master record to be used to derive
the cryptographic credential from the user's email address in all
browsers used by the user.  If that credential is compromised, the
master record can be rotated to add a new master record version to the
table.  In this demo, for simplicity, the rotation is triggered by a
GET request to "/rotateMasterRecord".  In production, the user would
report the compromise to an adminmistrator who would perform the
rotation and store the new version number in the user's record: this
is not implemented in this demo.

### Graphical pseudo-code

The slides of the powerpoint presentation in the repository file
`2F-crypto-authn.pptx` provide a step-by-step description of the code.

## Technical ingredients used in the demonstration

The backend runs under Nodejs and uses a MySQL database.  The [Pomcor
JavaScript Cryptographic Library
(PJCL)](https://github.com/fcorella/pjcl) is used on the frontend and
the backend.  A deterministic random bit generator (DRBG) initialized
with entropy sources is used to generate random bits for various
purposes (ECDSA signature, authentication challenge, etc.) and the
same DRBG initialized with the seed is used to generate the extended
key pair (ECDSA key pair generation, random generation of the secret
salt).

## How to run the demo

To run the demo you need to have an AWS account that allows you to send
mail.

Launch a free-tier eligible EC2 server running Amazon Linux 2 on AWS.
*Be sure to use Amazon Linux 2 rather than Amazon Linux 2023*; Amazon
Linux 2023 does not support the MySQL community server at this time.

Assign an IAM role to the server that allows it to send mail using the
AWS Simple Email Service (SES).

Install git (`sudo yum -y install git`) and clone this
repository into a directory `/home/ec2-user/2F-crypto-authn-demo`.

Change directory to `2F-crypto-authn-demo`, give execute permission to
install-demo and demo.mjs (`chmod a+x install-demo demo.mjs`), and run the installation
script (`sudo ./install-demo`).  The script will install
MySQL, Nodejs, and node modules including pjcl.  The script will ask
you for the public IP address of the server or a domain name that maps
to the IP address, and a sender address for the email verification
messages.

After installation, you can run the demo:

* As a systemd service, with the command `sudo systemctl start demo`.

* Or as an executable running under bash, with the command `sudo node
demo.mjs` while in the `2F-crypto-authn-demo` directory.

## Server certificate

The demo comes with a self-signed certificate `server-cert.pem` and
its associated private key `server-key.pem`.  If you want to avoid the
browser warnings, you can replace them with a domain certificate for
your chosen hostname purchased from a CA and its private key.

## Open source but not free

This software is provided as a demonstration of a method of user
authentication to a web site or web application that incorporates an
invention claimed by US patent 9,887,989.  The patent is owned by
Pomian & Corella, LLC, also known by the registered tradename Pomcor.

The copyright license of this repository does not wave any patent
rights.  Therefore non-experimental use of the software may require a
license to the patent.  You may use the [contact
form](https://pomcor.com/contact-us/) of the Pomcor site to request
one.

## See also

* General information about cryptographic authentication can be found
  in the [cryptographic authentication
  page](https://pomcor.com/cryptographic-authentication/) of the
  Pomcor site.
