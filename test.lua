local server = require "librserver".server;
local ctr = 0;
sender = server.test_mkecho({
	onreceived = function(text)
		print("got "..text);
		ctr = ctr + 1;
		if ctr < 2 then
			sender:send("magic!");
		end
	end;
});
sender:send("test1");
print("entering loop");
server.loop();
