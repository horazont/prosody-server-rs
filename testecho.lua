local server = require "testserver";
server.set_config({
	read_timeout = 2,
	send_timeout = 2,
});
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
