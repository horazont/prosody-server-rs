local server = require "testserver";
server.listen("0.0.0.0", 1234, {
	onconnect = function(sock)
		-- print("connection from "..sock:ip()..":"..tostring(sock:port()));
		-- print("new connection in lua");
	end,
	onincoming = function(sock, data)
		sock:write(data);
	end,
	ondisconnect = function(sock, err)
		if err ~= nil and err ~= "closed" then
			--print("ondisconnect", err)
		end
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
