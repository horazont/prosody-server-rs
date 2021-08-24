# Prosody Server Backend API

## Top-level API

- `backend.set_config(network_settings)` -> called on config updates and on start. may be nil if no config is supported.
- `backend.get_backend()` -> Return the backend name as string
- ! `backend.addserver(addr, port, listeners, read_size, tls_ctx)`

    - bind socket, send callbacks to listeners when things happen
    - direct TLS if tls_ctx is not nil
    - calls down to `wrapserver()` via `listen()` eventually

- ! `backend.listen(addr, port, listeners, config)`

    - binds socket, calls down to `wrapserver()`

- `backend.wrapserver(conn, addr, port, listeners, config)`

    - `conn` -> socket
    - `config`, mapping with keys:

        - `read_size`: something luasocket?
        - `tls_ctx`: tls context
        - `tls_direct`: I guess whether to enable that
        - `sni_hosts`: array I guess? not sure

    returns a "server" object

- ! `backend.addclient(addr, port, listeners, read_size, tls_ctx, typ, extra)`

    - `typ`: `tcp4` or `tcp6`
    -

- ! `backend.addtimer()`
- ! `backend.loop()`
- ! `backend.closeall()`
- ! `backend.setquitting()`
- ! `backend.wrapclient()`
- ! `backend.watchfd()`
- ! `backend.link()`
- `backend.event` some constants I guess?
- `backend.addevent()` -> libevent compat for watchfd, can probably steal the code
- `backend.timer.add_task` -> `addtimer` -> legacy API
- `backend.timer.stop` -> `closetimer` -> legacy API
- `backend.timer.reschedule` -> `reschedule` -> legacy API
- `backend.timer.to_absolute_time` -> `to_absolute_time` -> legacy API

## Server Objects

- `server.conn` -> socket
- `server.created` -> timestamp of creation
- `server.listeners` -> listener object (where the callbacks are)

    - those will be attached to the client!

- `server.read_size`, `server.tls_ctx`, `server.tls_direct` see above
- `server.hosts` SNI hosts, see above
- `server.sockname` -> addr
- `server.sockport` -> port
- `server.log` -> logger specific to the server

## Connection objects

- `conn.conn` -> socket
- `conn.created` -> timestamp
- `conn.listeners` -> where the callbacks are

    - `onerror`
    - `onattach`
    - `ondetach`
    - `onincoming`
    - `onreadtimeout`
    - `ondisconnect`
    - `ondrain`
    - `onstarttls`
    - `onstatus`
    - `onconnect`

- `conn.read_size`, `conn.tls_ctx`, `conn.tls_direct`
- `conn.id` connection id for logging i guess
- `conn.log` specific logger
- `conn.extra` free-form extra data... yeaaaah
