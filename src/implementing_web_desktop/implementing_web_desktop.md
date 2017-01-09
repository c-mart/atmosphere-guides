# Implementing Web Desktop (NoVNC Gateway)

## Overview / How It Works

[NoVNC](https://kanaka.github.io/noVNC/) ([readme](https://github.com/novnc/noVNC/blob/master/README.md)) is an HTML5 VNC client. It is used with Atmosphere to provide a seamless browser-based experience for users who wish to interact with their instance with a GUI, rather than a shell.

NoVNC has no built-in means of authentication, and the (open source) VNC protocol has no encryption, so the instance's VNC server is behind a gateway server, which authenticates connection requests from users and proxies a secure WebSocket which contains VNC traffic.

### Summary of Connection Workflow

- User browses to page for an active instance, clicks "Web Desktop" button
- Web browser sends POST request to Troposphere at `/web_desktop`
- Troposphere returns an HTTP redirect containing a signed token, e.g.
`https://webaccess.cyverse.org/vncws/?token=mysupersecrettoken&password=display`
- User's browser connects to NoVNC gateway server
- Nginx on the gateway server makes subrequest to auth_server Flask application
- auth_server decodes and attempts to verify token, returns HTTP code 200 (OK) or 401 (unauthorized), also returns the target IP of the instance
- If auth succeeds, Nginx serves static NoVNC client content, and proxies request for `/websockify` to the destination instance, port 4200
- Client establishes WebSocket connection to websockify on the instance
- On the instance, websockify un-wraps the session(?), forwards VNC connection to RealVNC Server
- VNC session launches

### NoVNC Connection ASCII Diagram

Once the initial token generation, authentication, proxying, etc. is complete, the network connections look like this:

```
("WS" = WebSocket)

[User's browser] <-- encrypted WS --> [Nginx on gateway server] <-- unencrypted WS --> [Websockify on instance] <-- VNC --> [RealVNC server on instance]
```

### How Authentication Works

Troposphere encrypts and signs a token that is embedded in a HTTP redirect that is served to the user. The gateway server decrypts the token and verifies that it was signed by Troposphere, before proxying the websocket connection to the instance. [itsdangerous](https://www.palletsprojects.com/p/itsdangerous/) is used for the token signing/verification functions. To accomplish this, both Troposphere and the gateway server know some secrets, a signing secret and a fingerprint secret (and a salt for each). Collectively, we'll call these the _shared secrets_.

### Components Deep Dive

#### On Atmosphere server: Troposphere

Troposphere presents user with a "Web Desktop" button. When the user clicks the button, a JavaScript handler submits an HTML form (POST request) to `/web_desktop`, containing an IP address of the instance. Upon receiving this request, Troposphere performs minimal checking to confirm that the user is an authenticated Atmosphere user, then [generates a redirect containing a token](https://github.com/cyverse/troposphere/blob/4db0a2ba6547437a5d5840679ff5cc4011bd87a4/troposphere/views/web_desktop.py), and serves it to the browser. The token authorizes its bearer (with a given browser fingerprint) to start a VNC session to a given IP address.

Token contains:

- Signature of client IP address
- Signture of browser fingerprint

#### On Gateway server: [NoVNC Authentication + Proxy](https://github.com/cyverse/nginx_novnc_auth)

Functionally does these things:

1. Authenticates NoVNC connection requests from users (as described above)
2. Proxies the WebSocket connection (carrying VNC traffic) to the instance
3. Provides TLS for the WebSocket connection between the user's browser and the gateway server

This is implemented as a simple [Flask](http://flask.pocoo.org/) application and some Nginx configuration.

The token is passed to gateway server via URL query string. Doesn't look for a cookie or anything, everything needed to connect is passed in the token.

```
https://webaccess.cyverse.org/vncws/?token=WyIxMjguMTk2LjY0LjE0MSIsImp0VDU2bldlV3VNQ2hyakdNdDRweWw2cHIyRBIsIjJmcUhFdnY4ZEFFFkNOLVhYUndpX05QaEY4NCJd.C08S7w.ajxE6VbmY7EVy4EW5o9tX96h-2w&password=display
```

Nginx is configured to use [ngx_http_auth_request_module?](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html). A subrequest containing the token is made to the Flask application (at `/auth`), and access is either granted or denied based on the response code.

The Flask application attempts to decode the token and validate the signature, using the shared secrets that are also known to Troposphere. It returns the HTTP status code (200 for valid or 401 for invalid fingerprint), and the instance IP address, to Nginx.

If the subrequest returns 200, then Nginx proxies the WebSocket connection to the websockify server on the instance.

#### On instance: websockify

[websockify](https://github.com/novnc/websockify) wraps a TCP connection in a WebSocket. This allows the VNC session to be carried from the user's browser, through the gateway server, to the VNC Server on the instance, and back.

Websockify is only configured to support a not encrypted(?) WebSocket, so a gateway server is required to wrap TLS around the WebSocket before serving it to the user.

#### On instance: RealVNC Server?

The instance runs the commercial RealVNC Server, which must be licensed?

VNC server is configured to accept a known weak password, because authentication is performed by the gateway server. It is also configured to only accept connections from localhost, and this avoids exposing an insecure VNC server to the outside world.

(This means that anyone who can obtain local login session to the instance can also create a VNC session.)

#### On Atmosphere server: atmosphere-ansible

At instance deploy time, atmosphere-ansible configures VNC Server and NoVNC WebSocket server on new instances via the [atmo-realvncserver](https://github.com/cyverse/atmosphere-ansible/tree/c49d4fb25bf1e0881ef694608e3b49b3ae654c27/ansible/roles/atmo-realvncserver) role and [atmo-novnc](https://github.com/cyverse/atmosphere-ansible/tree/master/ansible/roles/atmo-novnc) role, respectively.

These roles roughly do this:

- Check for existence of an X window server on the instance
- Install and configure RealVNC Server, set license
- Install NoVNC WebSocket server bits (websockify?)
- Start VNC Server with more configuration

Later in the instance deployment process, the [check_web_desktop_task](https://github.com/cyverse/atmosphere/blob/535ad5d3ebeb8ef75eb93edf8b3ea8eb8b17dbf7/service/tasks/driver.py#L1173) runs the atmo_check_novnc playbook (calling [atmo-check-novnc](https://github.com/cyverse/atmosphere-ansible/blob/master/ansible/roles/atmo-check-vnc/tasks/main.yml) role); this role checks to see if a VNC server is running. If this Ansible run succeeds, then the "Web desktop" field is set to true for the instance in the Atmosphere database. This causes the Web Desktop button to appear in the Troposphere UI when the instance page is loaded.

## Implementation Guide

First, choose a server to run the Nginx NoVNC Auth services. (It can't be the same as your Atmosphere server right now because of the way the Ansible is written, but this would be straightforward to change.) Define a "novnc_proxy" group in your Ansible hosts, containing the NoVNC proxy server you wish to use.

Ensure there is an OpenStack security rule allowing port 4200 from your NoVNC Gateway server's IP address

Define the following in the variables.yml that you will pass to Clank (see the Atmosphere [installation guide](install_guide.html#requirements-for-configuration)). Generate some random strings for the salts and secrets. (Collectively, we'll call these "shared secrets for web desktop".)

```
###
# Web Desktop
###
# Salts for signing/verifying authentication tokens and creading/decoding browser fingerprints
# WEB_DESKTOP_SIGNING_SALT: ""
# WEB_DESKTOP_FP_SALT: ""
# Shared secrets for signing/verifying authentication tokens and creading/decoding browser fingerprints
# WEB_DESKTOP_SIGNING_SECRET_KEY: ""
# WEB_DESKTOP_FP_SECRET_KEY: ""
# Troposphere feature flag to enable Web Desktop?
# WEB_DESKTOP_INCLUDE_LINK: False  
# Should be set to "https://my-novnc-gateway-server.com/vncws"
# WEB_DESKTOP_PROXY_URL: ""
# Should be set to ".my-novnc-gateway-server.com", allows Troposphere to set a cross-domain cookie readable by your NoVNC gateway server
# WEB_DESKTOP_PROXY_DOMAIN: ""  
```

Also define a RealVNC license key:

```
###
# VNC
###
# ATMOSPHERE_VNC_LICENSE: ""
```

Run Clank the [usual way](install_guide.html) to deploy Atmosphere, if you haven't done so already.

Clank will populate [troposphere's local.py](https://github.com/cyverse/troposphere/blob/88459d132388ecf14851733946965d391a452c71/troposphere/settings/local.py.j2
) with the shared secrets for web desktop.

Next, deploy the NoVNC Auth + Proxy server using the [utility playbook](https://github.com/cyverse/clank/blob/master/playbooks/utils/install_novnc_auth.yml) included with Clank -- more detailed instructions [here](https://github.com/cyverse/clank/tree/master/playbooks/utils).

(Should those instructions end up in this doc instead?)

Note that unlike Clank's usual behavior of deploying only to the local system, this playbook will run against the remote `novnc_proxy` host.

*To be continued / not tested yet*

## Questions
- How does http_auth_request_module get enabled on Nginx?
- The WebSocket is not encrypted all the way from the client to the Atmosphere instance, only to the proxy server (and then unencrypted to the instance), correct?
- Why do we use both a "signing key" and a "fingerprint key" here? Why two separate secrets?

## TODO
- install_novnc_auth.yml expects SSL certificate and key to already exist on target server but doesn't put them there. it should put them there.
- install_novnc_auth.yml uses some broken old Clank variables, update as follows:
```
# git diff playbooks/utils/install_novnc_auth.yml
diff --git a/playbooks/utils/install_novnc_auth.yml b/playbooks/utils/install_novnc_auth.yml
index 56379de..a4bd7bc 100644
--- a/playbooks/utils/install_novnc_auth.yml
+++ b/playbooks/utils/install_novnc_auth.yml
@@ -136,8 +136,8 @@
   vars:
     dhparam: "/etc/ssl/certs/dhparam.pem"
     key_size: 2048
-    privkey_pem: "{{ ATMO.nginx.KEY_PATH }}/{{ ATMO.nginx.KEY_FILE }}"
-    fullchain_pem: "{{ ATMO.nginx.COMBINED_CERT_PATH | default('/etc/ssl/certs/self_signed_combined.crt') }}"
+    privkey_pem: "{{ SSL_KEY }}"
+    fullchain_pem: "{{ COMBINED_CERT }}"
     ssl_cert: "{{ SSL_CERTIFICATE | default('/etc/ssl/certs/self-signed.crt') }}"
     bundle_cert: "{{ BUNDLE_CERT | default('/etc/ssl/certs/empty_bundle.crt') }}"
```
- `clank/group_vars/novnc_proxy` references old-style nested variables, which breaks stuff:
```
web_desktop_signing_secret_key: "{{ TROPO['local.py'].WEB_DESKTOP_SIGNING_SECRET_KEY }}"
web_desktop_signing_salt: "{{ TROPO['local.py'].WEB_DESKTOP_SIGNING_SALT }}"
web_desktop_fp_secret_key: "{{ TROPO['local.py'].WEB_DESKTOP_FP_SECRET_KEY }}"
web_desktop_fp_salt: "{{ TROPO['local.py'].WEB_DESKTOP_FP_SALT }}"
```
Change the four lines to
```
web_desktop_signing_secret_key: "{{ WEB_DESKTOP_SIGNING_SECRET_KEY }}"
web_desktop_signing_salt: "{{ WEB_DESKTOP_SIGNING_SALT }}"
web_desktop_fp_secret_key: "{{ WEB_DESKTOP_FP_SECRET_KEY }}"
web_desktop_fp_salt: "{{ WEB_DESKTOP_FP_SALT }}"
```
- Playbook doesn't know how to deal with SSL key encrypted with Ansible Vault
- Playbook should allow Nginx port through firewall
- In uwsgi log:
```
IOError: [Errno 2] No such file or directory: '/opt/dev/nginx_novnc_auth/logs/novnc_auth.log'
```
Playbook should create this file and make it owned by www-data

- Review/update https://github.com/cyverse/clank/tree/master/playbooks/utils/README.md
It doesnt say that the shared secrets for web desktop above must be defined, but they likely must be
- Should we recommend that network between the NoVNC proxy server and instances is private/secure, because websocket/VNC traffic between them is unencrypted?
- Should we recommend a border firewall / OpenStack security group to prevent VNC server on instances from being exposed to the world?
