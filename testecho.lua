package.cpath = "./target/" .. arg[1] .. "/?.so;" .. package.cpath;
local server = require "librserver".server;
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
});
server.loop();
