local server = require "librserver".server;
sender = server.test_mkecho({
	onreceived = function(text)
		print("got "..text);
	end;
});
sender:send("test1");
print("entering loop");
server.loop();
