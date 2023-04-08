# CaddyKnocker

This project is a proof-of-concept reimplementation of this [blog post](https://bilange.ca/pages/2022-05-12-privately-publish-selfhosted-services.html) in a standalone Python webapp, using [Caddy](https://caddyserver.com/)'s [forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth) directive to check whether an inbound HTTP connexion is permitted to go through and reach the web service or not. The target audience is people who self-host and uses Caddy as a reverse-proxy, for use on a small scale with a handful of people to authenticate (think: one person or a couple, max).

TLDR: This project brings the general idea of TCP [Port Knocking](https://en.wikipedia.org/wiki/Port_knocking) to Caddy-backed hostnames, hence the name. This app will initially deny access to protected `Caddyfile` config blocks, until a user enters from a configurable URL with a TOTP token to "whitelist" his current external IP address. CaddyKnocker lets connexions through via allowed whitelisted IPs or subnets.

## Usage

You can clone this directory (see warning) and use the provided Dockerfile to create an isolated environment for this app to run from (recommended). 

> **WARNING**: by cloning the repository, filesystem permissions for the `configuration.yaml` file are reset to be readable for everybody. This is awfully bad, because this app stores your TOTP Secret in plain text in the configuration file. On Unix based OS, you may want to tighten up the security of this file by typing `chmod go-r configuration.yaml`. Upon startup, the app will complain about too permissive rights to this file (and outright exits immediately) as a reminder.

To build a docker image from the cloned directory, type:

```
git clone https://github.com/bilange/caddyknocker.git
cd caddyknocker
docker build -t caddyknocker .
docker run -d --network caddy --name=caddyknocker --rm caddyknocker
```

The name of the container might be changed to your likings, but note that the example configuration described below points to `caddyknocker` as being this app, so you may want to adjust your config if you change it. Also, this container needs to be on the same [docker network](https://docs.docker.com/network/) as your running Caddy instance, as Caddy talks to this app for every HTTP connection and for initial authentication.

Note that the last line above only runs a "live" instance on terminal, interactively, and terminates on `Ctrl-C`. You may want to use docker compose to have a permanent setup, similar to:

```yaml
version: '3.5'

networks:
  caddy:
    driver: bridge
    name: caddy

services:
  caddyknocker:
    container_name: caddyknocker
    restart: always
    build:
      context: /path/to/cloned/caddyknocker
    image: caddyknocker
    networks:
      - caddy   # Must reside on the SAME network as caddy, for... obvious reasons???
    ports:
      - "80"
    volumes:
      - /path/to/cloned/caddyknocker/configuration.yaml:/app/configuration.yaml
  caddy: 
    # ...
```

If you're feeling ~~lucky~~ adventurous, you can also execute the Python app natively this way:

```bash
virtualenv env
source env/bin/activate
pip install -r requirements.txt
python3 app.py
```

This will give you the opportunity to hack around the application to fit it to your needs. There are enough code comments, I hope, to guide you along the way.

### Protecting a web service

Caddy must be configured this way for every service that you want to protect (for example, say a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance):

```
https://bitwarden.example.com {
        route { 
                forward_auth caddyknocker:8000 {
                        uri /check
                        copy_headers X-Forwarded-For
                }
                # other 'normal' directives for this host goes here: 
                reverse_proxy http://bitwarden:3000
        }
}
```

Every time a connection is made to `bitwarden.example.com`, Caddy first initiates a connection to `http://caddyknocker:8000/check`. The `caddyknocker` host shown in this config above points to **this** Python app. This app will, for requests made on`/check`, either validates or deny access, depending on the IP.  This is done with the assistance of Caddy, who will act according to it's [docs about forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth):

* « *If the upstream responds with a 2xx status code, then access is granted (...) and handling continues* » , then Caddy will hit the next line in my example configuration above with the `reverse_proxy` directive, being the service you wanted to protect.
* « *Otherwise, if the upstream responds with any other status code, then the upstream's response is copied back to the client. This response should typically involve a redirect to login page of the authentication gateway.* ». In the case of this app, it is configured to answer with a [HTTP 301 Moved Permanently](https://en.wikipedia.org/wiki/HTTP_301), with a random external URL of your choosings. The idea here is to forward away the refused incoming connection.

### Accessing protected services

When you want to access your services, you have basically two ways to do so:

* Permanently allowing known subnets by modifying the configuration file (more on the configuration file later)
* "Knock-in" (permitting access on-demand) on a per-IP basis, by hitting a specific URL that you have implemented somewhere in your `Caddyfile` config. This knock-in URL will point to CaddyKnocker and verify the incoming connection with a TOTP Code you have provided. Knocking in is implemented this way (adapt the public URL for your needs): 

```
https://www.example.com {
        handle /api/0/getInfo { # can be long and arbitrary
                rewrite * /knock   # tells Caddy to always redirect the path to /knock (configurable in-app), regardless of the path in 'handle' above
                reverse_proxy http://caddyknocker:8000
        }

        # other regular Caddy directives goes here for regular access to this host
}
```

(Note: `/api/0/getInfo` is something we invented from scratch for this example; you can use any URL you want as your authenticator endpoint)

To authenticate your IP, simply hit `https://www.example.com/api/0/getInfo` and provide the header `Nonce: (TOTP Code)`, where `Nonce` is a keyword this app looks for (configurable in-app) and `TOTP Code` is a TOTP code that was generated for usage (`123456`). For a complete example of a client connecting, with [curl](https://curl.se/):

```
$ curl -i https://www.example.com/api/0/getInfo -H 'Nonce: 248712'
HTTP/2 204 
server: Microsoft-IIS/10.0
x-whitelist: True
```

When authenticating correctly, this response comes with a `x-whitelist: True` header lets you know that you have successfully authorized yourself, as well as a body that says simply "OK". Next time there is a request from this public IP on all your Caddy protected services, you will automatically get through, for the next 24 hours (configurable).

#### Mobile: remotely access to your protected services on the go

Assuming you want to unlock your services when you're out (say, at work or at someone's house), using Wifi on your Android smartphone, you may use [HTTP Shortcuts](https://http-shortcuts.rmy.ch), an Android app (free! both as in speech and in beer) that lets you configure a profile for to connect to your Caddy "knock-in" endpoint. It works like this:

* I will assume that you have somehow access to your TOTP codes on your mobile device,  with for example AndOTP (now abandoned by the developer 😞) or [Aegis](https://getaegis.app/) (feature-wise identical) or similar. Also, for faster access, make sure you are able to copy your TOTP code from your Android app into your clipboard.
* In the HTTP Shortcuts app:
  * Create a variable that will hold your TOTP code. Variables are set up in the hamburger menu "..." in the top right corner of the app main screen and select "Variables". Only set a variable name, say `totp` (this will be referenced later), and no value (leave it blank), it will be modified later.
  * Create a new "Regular HTTP shortcut" using the "+" button in the lower right. The settings for this "Regular HTTP shortcut" are all of the following:
    * "Scripting" section: Run before execution: `setVariable('totp',getClipboardContent())`, where `totp` is the same name as you set above in the Variables section.
    * "Basic Request Settings" section:: Method: `GET` . URL: it should be the full URL that points to the Caddy config where you expose `http://caddyknocker:8000/knock`. As the example above: `https://www.example.com/api/0/getInfo`
    * "Request Headers" section: create one single header configured like this:
      * The Header name MUST match the configuration of CaddyKnocker with it's `Server-Security-Header` variable. (By default, it is set to be named `Nonce`)
      * The value must be set as `{totp}` with the curly braces, `totp` refers to the name of the Variable we set up in the section Variables above.
    * "Response Handling" section: you might want to change the Display Type to "Dialog Window" instead of "Toast Popup".  The reason is that HTTP Shortcuts will notify you in a "Toast Popup" that you copied the clipboard contents, and **then** will give the connexion response **after** the first toast has disapeared. This is a very minor annoyance, but will lose a few seconds waiting after a Toast Notification to go away. Sidenote: if you instead select the "Fullscreen Window" you can check "Show Meta Information" which will print out the complete raw HTTP response coming from the server instead. Handy for debugging.
  * Now in the main window of HTTP Shortcuts, you can long-press on your Shortcut and select "Place on Home Screen". This will place an icon on your home screen for quick launching (you won't even have to open the app to call the HTTP Shortcut)
* Once everything is set up, "knocking-in" when you're trying to connect from an unknown IP is a matter of simply doing this:
  * Opening up your TOTP app and copying your generated TOTP code in the clipboard
  * Tapping on the "HTTP Shortcut" Homescreen shortcut you made above, this will execute your HTTP Shortcut and use your TOTP code from the clipboard.
  * HTTP Shortcut will print out the response body from CaddyKnocker, essentially either OK or FAIL. You might want to enable "Fullscreen Window" as explained above to further diagnose.

**OR**, if you prefer the command-line instead (you ARE using Caddy, after all 😃), here's a method that works with Termux on Android:

* Install from the F-Droid store [Termux](https://f-droid.org/en/packages/com.termux/) as well as [Termux:API](https://f-droid.org/en/packages/com.termux.api/). The latter gives clipboard access to the shell and is practically required. (You don't want to type out your TOTP code on a software keyboard, do you?)
* In Termux, type `pkg install termux-api`
* To knock-in, execute something like `curl -i https://www.example.com/api/0/getInfo -H 'Nonce: $(termux-clipboard-get)'`, after fetching your TOTP code in your TOTP app. Even better, edit `~/.bashrc` and create an alias like `alias letmein="curl -i https://www.example.com/api/0/getInfo -H 'Nonce: $(termux-clipboard-get)"`, so you only have to type `letmein` on the shell.

---

On iOS? I'm sorry, I can't be of much help, I don't have iThings at home. But I'm sure there are similar tools to achieve this out there.

### Refusing access

Whether you entered a wrong TOTP code or if you try to hit your protected Caddy services without being whitelisted beforehand, this response will be sent to the client (where `Location: https://www.zombo.com` is configurable and will send away the client trying to connect):

```
HTTP/2 301 
location: https://www.zombo.com
server: Microsoft-IIS/10.0
x-whitelist: False

FAIL
```

## Notifications

There is support to send a HTTP notification to a [Gotify](https://gotify.net/) server whenever someone tries to knock-in. The code is very rudimental but "generic", so you may be able to use another notification service of your choosing if you can simply use HTTP forms in POST or GET to send a message. Your milage may vary as other web services aren't tested.

Notifications are to let you know on the success (or failure) of people accessing your `/knock` endpoint. Ideally, that should be only you!

## Configuration

Configuration for this app is done via `configuration.yaml`, and you are encouraged (in fact, enforced) to edit this file to your likings.

You definitely want to change (or check) at least a few lines in the configuration file:

* `TOTP-Secret`: This is a TOTP secret that ideally only you should know, as it serves as your "password" so to speak to authenticate yourself on the `/knock` endpoint. You can use this [TOTP Secret Generator](https://www.token2.com/site/page/totp-toolset) to generate a new TOTP secret (clicking on "random" below the secret pseudo-generates a secret in-browser; clicking on "True random" pokes an [external server](https://qrng.anu.edu.au) but is rate-limited to 1 request per minute), and paste the secret on this configuration line (and insert it as well in your TOTP manager of choice, of course). You **definitely** want to change the default value, as this secret token is [used](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) as an example [everywhere](https://duckduckgo.com/?q=JBSWY3DPEHPK3PXP&t=h_&ia=web) and as such is insecure.
* `Server-Redirect-Failures-To`: This the URL being used for any client trying to reach a secured endpoint without proper authentication. You may want to change the default [Zombo.com](https://en.wikipedia.org/wiki/Zombo.com) to something more to your likings, like the root of your domain or something.
* `API-Check-Path`: This line is crucial, but may be left as a default if you'd like. What is important is that this setting matches your Caddy configuration when you're trying to secure one service. This is the path that is being used by Caddy to check with this app whether or not a certain IP is already whitelisted or not. This variable changes the definition of `/check`.  See the section "Protecting a web service" for details.
* `API-Knock-Path`: This line is crucial, but may be left as a default if you'd like. Somewhere in your Caddy config, there should be a path that is being rerouted to the `/knock` endpoint, used to authenticate yourself. This variable changes the definition of `/knock`. See the section "Accessing protected services" for the Caddy example config.
* `Server-Fowarded-IP-Header`: This line is crucial, but the default should work. Caddy HAS to pass the `X-Forwarded-For` header to internal endpoints when calling `reverse_proxy` and `forward_auth` directives. This is the "external" IP, from Caddy's point of view, of the client trying to connect. This variable is for if you want to use a custom header when passing the IP from caddy to the app.
* `Server-Security-Header`: This is the name of the HTTP header the client uses to authenticates itself. If you change this (default is `Nonce`) for, say `MyNewHeader`, you will have to call your knock-in endpoint with `MyNewHeader: 123456` instead of `Nonce: 123456`. The value of this HTTP header is your TOTP generated code.
* `Allowed-Expiration`: The amount of hours an authenticated IP is valid for.
* `Allowed-Subnets`: If you are reaching Caddy (and it's underlying services) inside your LAN and want to be permanently whitelisted from your LAN subnet, you can add a line like this one to permanently allow yourself (note the IP/CIDR notation):

```
Allowed-Subnets: 
- 192.168.100.0/24
```

* `Configuration-Sync`: Every 3600 seconds (by default), the configuration will be synced on disk, saving any new whitelisted IPs being allowed access. This should then give persistence between CaddyKnocker sessions (say, after a server reboot)
* `Allowed-IPs`: This is a list of IPs that has being accepted with a valid TOTP. Note that this variable is configured as a list of values. The `expiration` variable is the [UNIX Timestamp](https://en.wikipedia.org/wiki/Unix_time) of the moment the whitelist expires. You can also put `0` for no expiration (for example if you want to allow your static work IP to always reach your secured endpoints)

```
Allowed-IPs:
- expiration: 0
  ip: 8.8.8.8
- expiration: 1679751960
  ip: 1.1.1.1
```

* `ServerPort`: Port on which this app listens to. To cover for the use case of running through a Docker container with a non-root user, this has been set to 8000 by default. Be aware that running it with ports < 1024 requires root. 

### Configuration for Notifications
* `Notify-URL`: The HTTP URL we need to hit to reach the notification server, if we want one. Leave empty to disable notification feature globally.
* `Notify-On-Knock-Successful`: Sends a notification if there was a valid authentication attempt. (**true** / false)
* `Notify-On-Knock-Failure`: Sends a notification if there was an INVALID authentication attempt. (**true** / false)
* `Notify-On-Knock-Close`: Sends a notification when a previously valid authentication expires. (**true** / false)
* `Notify-HTTP-Method`: Either POST or GET, depending on the need of your notification service. 
* `Notify-HTTP-Payload`: This value is a list of parameters being sent in the form data (for HTTP POST), or URL parameters (for HTTP GET), when sending a notification. Any number of parameters can be sent; you can enter anything you like there as see fit. There are also the special macros `{ip}` and `{knock_status}` that gets replaced with the requester's IP, and a simple message about the current knock-in request.

As a complete example, here are the parameters required for a Gotify server to accept a notification: 

```
  Notify-URL: http://gotify-host/message?token=GOTIFYTOKEN 
  Notify-HTTP-Method: POST
  Notify-HTTP-Form-Payload: 
    message: 'My message here with those variable added in: {ip} {knock_status}'
    priority: 3
    title: 'Message from CaddyKnocker'
``` 

### Protections for the `/knock` endpoint
Since the `/knock` endpoint is meant to be exposed to the public web and is somewhat important security-wise, here are two optional protections that you can configure.

#### TOTP Replay protection
By using the `Server-Reuses-TOTP` variable, you can define if more than one use of the same valid TOTP code is permitted. `Server-Reuses-TOTP` set to true will permite multiple use of the same TOTP code. If set to false, you'll have to wait for the next generated TOTP code to authorize yourself again.
 
#### DoS protection
You can optionally enable a basic DoS protection on the `/knock` endpoint. By default and if activated, if more than 3 hits with a wrong TOTP code has been made to `/knock` in the last 60 seconds, replies made to the client will be increasingly more delayed.

This protection can be enabled by setting `Server-Knock-Flood-Protection` to true, and parameters to the theshold can be set by adjusting the `Server-Knock-Flood-Protection-Duration` and `Server-Knock-Flood-Protection-Times` variable.

This only affects your `/knock` endpoint, and only for connections with a wrong TOTP code (meaning that a valid TOTP code won't get throttled).

### Environment variables

#### Configuration location (`CONFIG`)

You can set the `CONFIG` environment variable if you want to change the configuration location. By default, it will be set as `configuration.yaml` in the same directory as the main app.py file.