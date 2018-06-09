## acme-alpn-proxy

This program implements an experimental TLS ALPN proxy in order to implement downtime-free validation and renewal of Let's Encrypt certificates using the port 443 [TLS-ALPN-01 challenge](https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01).

It works in the following way:

- Upon starting, it listens on `127.0.0.1:21443/tcp`. 
  - This listener pre-reads the first (up to ~16KiB) packet and checks whether:
    - It is a ClientHello TLS record
    - It contains the ALPN TLS extension
    - It contains the `acme/tls-1` ALPN protocol
  - If these prerequisites are fulfilled, the program will proxy the TCP connection to `127.0.0.1:31443/tcp` (where you should run e.g. Certbot's standalone TLS-ALPN-01 authenticator)
  - Otherwise, the listener will proxy the TCP connection to `127.0.0.1:443/tcp`.
  - In both cases, the program will copy the ClientHello TLS record as well.
  - After the listener is started, the program applies an iptables and ip6tables rule to redirect any incoming connections on `443/tcp` to the program (that is already listening `21443/tcp`).
- Upon receiving the kill (SIGINT) signal (or the `stop` command):
  - The program removes the iptables redirects
  - The listener will no longer accept new connections
  - The listener will wait for the existing already-proxied connections to conclude before it dies.

## Features

- Web server and ACME client agnostic
- No downtime of connections at any point
- Safe, idempotent operation
- Single, dependency free (apart from iptables which you should already have) binary

## Usage

```bash
# Download it once to your Linux system
sudo curl -L -o /usr/sbin/acme-alpn-proxy "https://github.com/letsdebug/acme-alpn-proxy/releases/download/0.2.0/acme-alpn-proxy"

# Invoke your ACME client
# This is a speculative example, the standalone authenticator in Certbot does not yet support TLS-ALPN-01
certbot certonly -d example.org -a standalone \
--preferred-challenges tls-alpn-01 --tls-alpn-01-port 31443 \
--pre-hook "/usr/sbin/acme-alpn-proxy start &" --post-hook "/usr/sbin/acme-alpn-proxy stop &"
```

### Customization

#### Change the fallback destination for non acme/tls-1 connections
By default it is `127.0.0.1:443`, but you can customize it by using e.g.

    acme-alpn-proxy -fallback 127.0.0.1:8443 start

#### Change the destination for acme/tls-1 connections
By default, `127.0.0.1:31443`, but can be customized:

    acme-alpn-proxy -alpn 127.0.0.1:8443 start

#### Change the iptables rule that is added and removed

By default:

	-p tcp --dport 443 -j REDIRECT --to-port 21443 -m comment --comment acme-alpn-proxy

but can be overridden with the `ACME_ALPN_PROXY_RULESPEC` env variable.

(`-t nat -A/-D PREROUTING` is prepended for addition/deletion of rules, respectively).

#### Change the pidfile destination
By default in `/var/run/acme-alpn-proxy.pid`, but you can override it with the `ACME_ALPN_PROXY_PIDFILE` env variable.