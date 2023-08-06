export function readCSRFCookie() {
    const match = document.cookie.match(/CSRF\s*=\s*([A-Fa-f0-9]+\-[A-Fa-f0-9]+)/);
    if (match !== null) {
	return match[1];	
    }
    else {
	return false;
    }
}

export function checkLogin(submitEvent) {
    const emailElt = document.getElementById("email");
    const email = emailElt.value.replace(/^\s+/,"").replace(/\s+$/,"");
    emailElt.value = email;
    let s = "";
    if (email == "") {
        s += "Please enter your email address";
    }
    else if (email.search(/^[A-Za-z0-9]+@[A-Za-z0-9]+(\.[A-Za-z0-9]+)*\.[A-Za-z]+$/) == -1) {
        s += "Invalid email address";
    }
    const CSRFTokenElt = document.getElementById("CSRFToken");
    const CSRFCookie = readCSRFCookie();
    if (!CSRFCookie) {
	s += "No CSRF cookie found; try refreshing the page<br>";
    }
    else {
	CSRFTokenElt.value = CSRFCookie;
    }
    if (s) {
        document.getElementById("loginError").innerHTML = s;
        submitEvent.preventDefault();
    }
    else {
	const credentialFoundElt = document.getElementById("credentialFound");
	const prefix = "2F-demo-app:" + email.toUpperCase() + ":";
	if (localStorage[prefix + "privKeyHex_d"]) {
	    credentialFoundElt.value = "yes";
	}
	else {
	    credentialFoundElt.value = "no";
	}
    }
}
