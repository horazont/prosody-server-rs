local server_impl = require "librserver".server;
local add_task_impl = server_impl._add_task;
local sslconfig = require"util.sslconfig";

local _ENV = nil;

local function add_task(timeout, cb, params)
	return add_task_impl(timeout, function(t, h)
		return cb(t, h, params)
	end)
end

return {
	-- TIMER FUNCTIONS
	add_task = add_task;
	timer = {
		add_task = add_task;
		stop = function(fd)
            fd:close();
		end;
		reschedule = function(fd, t)
			fd:reschedule(t);
		end;
	};

	-- SERVER FUNCTIONS
	listen = server_impl.listen;

	-- TLS FUNCTIONS
	tls_builder = function()
		return sslconfig._new(server_impl.new_tls_config);
	end,

	-- MAIN LOOP FUNCTIONS
	loop = server_impl.loop;
}
