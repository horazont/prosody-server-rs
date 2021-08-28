local server = require "testserver";
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
    tls_config = {
		sni_names = {
			["localhost"] = {
				certificate = "./localhost.crt",
				key = "./localhost.key",
			},
		},
	},
});
server.loop();
