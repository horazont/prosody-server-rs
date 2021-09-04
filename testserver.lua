local backend_name = arg[1];
local server;
if backend_name == "rust" then
	package.cpath = "./target/" .. (arg[2] or "debug") .. "/?.so;" .. package.cpath;
end
local impl = require("net.server_" .. backend_name);
if impl.hook_signal then
	for _, sigkind in pairs({"SIGINT", "SIGTERM"}) do
		assert(impl.hook_signal(sigkind, function()
			print(sigkind.." delivered, shutting down")
			impl.shutdown();
		end));
	end
end
return impl;
