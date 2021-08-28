package.cpath = "./target/" .. arg[1] .. "/?.so;" .. package.cpath;
local server = require"net.server";
local task_1s = server.add_task(1, function(t)
	print("1s at "..tostring(t));
	return 1;
end)
server.add_task(0.3, function(t)
	print("0.3s at "..tostring(t));
	return 0.3;
end)
server.add_task(1.5, function(t)
	print("here goes the boom boom at "..tostring(t));
	print("I'll also make the 1s timer run right now");
	server.timer.reschedule(task_1s, 0);
	error "boom";
end)
server.loop();
