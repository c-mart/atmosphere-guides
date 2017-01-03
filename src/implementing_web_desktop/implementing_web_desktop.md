# Implementing Web Desktop (NoVNC Proxy)

## Overview / How It Works

[NoVNC](https://kanaka.github.io/noVNC/) ([readme](https://github.com/novnc/noVNC/blob/master/README.md)) is an HTML5 VNC client. It is used with Atmosphere to provide a seamless experience for users who wish to interact with their instance with a GUI rather than a shell.

### Server Components

#### [Nginx NoVNC authentication/proxy](https://github.com/cyverse/nginx_novnc_auth)

This code contains a Flask application that authenticates users, and an Nginx configuration to proxy websockets.

It can be installed on the same server that runs GateOne.

#### VNC Server and NoVNC Server on instance

The instance runs the commercial VNC Server (which must be licensed).

#### atmosphere-ansible

atmosphere-ansible configures VNC Server and NoVNC websocket server on new instances via [40_novnc_install.yml](https://github.com/cyverse/atmosphere-ansible/blob/master/ansible/playbooks/instance_deploy/40_novnc_install.yml) and the [atmo-novnc](https://github.com/cyverse/atmosphere-ansible/tree/master/ansible/roles/atmo-novnc) role.

### Workflows

#### At Instance Deploy Time
atmosphere-ansible roughly does this:

- Checks for existence of an X window server on the instance
- Installs NoVNC websocket server bits (Julian, can you clarify?)
- Is a VNC server installed by atmosphere-ansible or is it expected to already be available on the instances?
- Starts and configures VNC Server, sets license
- Sets the "Web desktop" value in Atmosphere database (how?)

Then, the Web Desktop button will appear when the instance page is loaded.

#### At Connection Time
- User browses to page for an active instance, clicks "Web Desktop" button
- NoVNC client code loads in browser, client establishes a web socket to the instance via NoVNC proxy
- How does auth work?
- What else?
- VNC session launches

## Implementation Guide

Choose a server to run the Nginx NoVNC Auth services

...

## Questions
- What exactly does the NoVNC server component on instances do?
- Regarding terminology, does the "NoVNC Proxy" run on the Atmosphere instance or on the Nginx server?
- How does Atmosphere come to know that an instance has web desktop enabled?
- Why do we have a NoVNC proxy? For auth?
- How is auth handled for the websocket, i.e. how does the instance authenticate users? Shared secret between instance and NoVNC proxy, and NoVNC proxy somehow confirms that requests came from Atmosphere?
