implement Portmapper;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, p32, popaque: import sunrpc;
	IO, Parse, Badrpc: import sunrpc;
	Badprog, Badproc, Badprocargs: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "../lib/portmaprpc.m";
	portmaprpc: Portmaprpc;
	Tportmap, Rportmap, Map: import portmaprpc;

Portmapper: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
addr := "net!*!sunrpc";

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	portmaprpc = load Portmaprpc Portmaprpc->PATH;
	portmaprpc->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] [addr]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	case len args {
	0 =>	;
	1 =>	addr = hd args;
	* =>	arg->usage();
	}

	(ok, aconn) := sys->announce(addr);
	if(ok < 0)
		fail(sprint("announce %q: %r", addr));
	say("announced");
	for(;;) {
		(lok, lconn) := sys->listen(aconn);
		if(lok < 0) {
			warn(sprint("listen: %r"));
			continue;
		}
		fd := sys->open(lconn.dir+"/data", Sys->ORDWR);
		if(fd == nil) {
			warn(sprint("open new connection: %r"));
			continue;
		}
		say("new connection");
		spawn srv(fd);
		lconn.cfd = fd = nil;
	}
}

alarm(pid: int, pidc: chan of int)
{
	pidc <-= sys->pctl(0, nil);
	sys->sleep(10*1000);
	kill(pid);
}

srv(fd: ref Sys->FD)
{
	spawn alarm(sys->pctl(0, nil), pidc := chan of int);
	apid := <-pidc;
	for(;;) {
		err := transact(fd);
		if(err != nil) {
			warn(err);
			break;
		}
	}
	kill(apid);
}

transact(fd: ref Sys->FD): string
{
	say("transact");
	tt: ref Tportmap;
	{
		tt = sunrpc->read(fd, ref Tportmap.Null);
	} exception e {
	Badrpc =>
		r := e.t1;
		return sunrpc->write(fd, r);
	IO =>
		return "reading request: "+e;
	Parse =>
		return "parsing request: "+e;
	}

	say("have portmap request");

	r: ref Rportmap;
	nullauth: Auth;
	nullauth.which = sunrpc->Anone;
	rok := ref Rrpc.Success  (tt.r.xid, nullauth);
	rbad := ref Rrpc.Systemerr (tt.r.xid, nullauth);
	pick t := tt {
	Null =>
		r = ref Rportmap.Null (rok);
	Set =>
		# xxx implement
		r = ref Rportmap.Set (rok, 0);
	Unset =>
		# xxx implement
		r = ref Rportmap.Unset (rok, 0);
	Getport =>
		# xxx implement
		r = ref Rportmap.Getport (rok, 0);
	Dump =>
		# xxx implement
		r = ref Rportmap.Dump (rok, array[0] of Map);
	Callit =>
		return sunrpc->write(fd, rbad);
	* =>
		raise "internal error";
	}
	say("have portmap response");
	return sunrpc->write(fd, r);
}

kill(pid: int)
{
	p := sprint("/prog/%d/ctl", pid);
	fd := sys->open(p, Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "kill");
}

hex(d: array of byte): string
{
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint("%02x", int d[i]);
	return s;
}

warn(s: string)
{
	sys->fprint(sys->fildes(2), "%s\n", s);
}

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	warn(s);
	raise "fail:"+s;
}
