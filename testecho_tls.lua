local server = require "testserver";
server.set_config({
	ssl_handshake_timeout = 2,
})
server.listen("0.0.0.0", 1234, {
	onconnect = function(sock)
		-- print("connection from "..sock:ip()..":"..tostring(sock:port()));
		print("new connection in lua");
	end,
	onincoming = function(sock, data)
		sock:write(data);
	end,
	ondisconnect = function(sock)
		print("read side closed, draining")
		sock:close();
	end,
}, {
    tls_direct = true,
    tls_ctx = assert(server:tls_builder():apply({
		mode = "server",
		-- protocol is completely ignored in rust for now, but it is needed for the existing LuaSec backends
		protocol = "tlsv1_2+",
		certificate = "./certs/localhost.crt",
		key = "./certs/localhost.key",
	}):build()),
});
server.loop();
