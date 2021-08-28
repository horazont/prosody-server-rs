package.cpath = "./target/" .. arg[1] .. "/?.so;" .. package.cpath;
local server = require "librserver".server;
server.listen("0.0.0.0", 1234, {
	onconnect = function(sock)
		print("oh yeah, Lua got hold of a PLAIN TEXT socket \\o/")
	end,
	onstarttls = function(sock, ctx)
		print("oh yeah, Lua got hold of a TLS socket \\o/")
	end,
});
server.loop();
