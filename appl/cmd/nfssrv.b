implement Nfssrv;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, p32, popaque: import sunrpc;
	IO, Parse, Badrpc: import sunrpc;
	Badrpcversion, Badprog, Badproc, Badprocargs: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "../lib/mntrpc.m";
	mntrpc: Mntrpc;
	Tmnt, Rmnt: import mntrpc;

Nfssrv: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
nfsport := 2049;
mntport := 39422;

regfd: ref Sys->FD;  # global, so we keep a reference until nfssrv dies

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	mntrpc = load Mntrpc Mntrpc->PATH;
	mntrpc->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] [-n nfsport] [-m mntport]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		'n' =>	nfsport = int arg->earg();
		'm' =>	mntport = int arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(args != nil)
		arg->usage();

	regfd = sys->open("/chan/portmapper", Sys->OWRITE);
	if(regfd == nil)
		failall(sprint("open /chan/portmapper: %r"));
	if(sys->fprint(regfd, "add %d %d tcp %d\n", Mntrpc->ProgMnt, Mntrpc->VersMnt, mntport) < 0)
		failall(sprint("registering mnt: %r"));

	spawn nfslisten();
	spawn mntlisten();
}

nfslisten()
{
}

mntlisten()
{
	mntaddr := sprint("net!*!%d", mntport);
	(ok, aconn) := sys->announce(mntaddr);
	if(ok < 0)
		failall(sprint("announce %q: %r", mntaddr));
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
		spawn mntsrv(fd);
		lconn.cfd = fd = nil;
	}
}

alarm(pid: int, pidc: chan of int)
{
	pidc <-= sys->pctl(0, nil);
	sys->sleep(10*1000);
	kill(pid);
}

mntsrv(fd: ref Sys->FD)
{
	spawn alarm(sys->pctl(0, nil), pidc := chan of int);
	apid := <-pidc;
	for(;;) {
		err := mnttransact(fd);
		if(err != nil) {
			warn(err);
			break;
		}
	}
	kill(apid);
}

mnttransact(fd: ref Sys->FD): string
{
	say("mnttransact");
	tt: ref Tmnt;
	{
		tt = sunrpc->read(fd, ref Tmnt.Null);
	} exception e {
	Badrpc =>
		r := e.t1;
		return sunrpc->write(fd, r);
	IO =>
		return "reading request: "+e;
	Parse =>
		return "parsing request: "+e;
	}

	say("have mnt request");

	r: ref Rmnt;
	nullauth: Auth;
	nullauth.which = sunrpc->Anone;
	rok := ref Rrpc.Success  (tt.r.xid, nullauth);
	rbad := ref Rrpc.Systemerr (tt.r.xid, nullauth);
	pick t := tt {
	Null =>
		r = ref Rmnt.Null (rok);
	Mnt =>
		r = ref Rmnt.Mnt (rok, Mntrpc->MNT3perm, nil, nil);
	Dump =>
		r = ref Rmnt.Dump (rok, nil);
	Umnt =>
		r = ref Rmnt.Umnt (rok);
	Umntall =>
		r = ref Rmnt.Umntall (rok);
	Export =>
		r = ref Rmnt.Export (rok, nil);
	* =>
		raise "internal error";
	}
	say("have mnt response");
	return sunrpc->write(fd, r);
}


progctl(pid: int, s: string)
{
	p := sprint("/prog/%d/ctl", pid);
	fd := sys->open(p, Sys->OWRITE);
	if(fd != nil)
		sys->fprint(fd, "%s", s);
}

kill(pid: int)
{
	progctl(pid, "kill");
}

killgrp(pid: int)
{
	progctl(pid, "killgrp");
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

failall(s: string)
{
	warn(s);
	killgrp(sys->pctl(0, nil));
	raise "fail:"+s;
}

fail(s: string)
{
	warn(s);
	raise "fail:"+s;
}
