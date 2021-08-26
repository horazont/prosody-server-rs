local server = require "librserver".server;
server.add_task(1, function()
	print("1s");
	return 1;
end)
server.add_task(0.3, function()
	print("0.3s");
	return 0.3;
end)
server.add_task(1.5, function()
	print("here goes the boom boom");
	error "boom";
end)
server.loop();
