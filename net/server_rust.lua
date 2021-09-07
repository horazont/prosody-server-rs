local type = type;
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

	-- CLIENT FUNCTIONS
	addclient = function(addr, port, listeners, socket_read_size, tls_ctx, typ, extra)
		local read_size = socket_read_size;
		if read_size == "*a" then
			-- TODO: make configurable
			read_size = 8192
		elseif type(read_size) == "string" then
			error("read_size "..read_size.." not supported by this backend, sorry")
		end
		return server_impl.addclient(addr, port, listeners, read_size, tls_ctx, typ, extra);
	end;

	-- TLS FUNCTIONS
	tls_builder = function()
		return sslconfig._new(server_impl.new_tls_config);
	end,

	-- BARE FD FUNCTIONS
	watchfd = function(maybe_fd, onreadable, onwritable)
		local fd = maybe_fd;
		if type(fd) ~= "number" then
			fd = fd:getfd();
		end
		return server_impl.watchfd(fd, onreadable, onwritable);
	end;

	-- SIGNAL FUNCTIONS
	hook_signal = server_impl.hook_signal;

	-- MAIN LOOP FUNCTIONS
	loop = server_impl.loop;
	shutdown = server_impl.shutdown;
}
