local backend_name = arg[1];
local server;
if backend_name == "rust" then
	package.cpath = "./target/" .. (arg[2] or "debug") .. "/?.so;" .. package.cpath;
end
return require("net.server_" .. backend_name);
