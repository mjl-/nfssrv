implement Portmapper;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "string.m";
	str: String;
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

ProtTcp:	con 6;
ProtUdp:	con 17;

Reg: adt {
	map:	Map;
	fid:	int;
};

delregfidc: chan of int; # fid
addregc: chan of (ref Reg, chan of string);  # new registration, error response chan
delmapc: chan of (Map, chan of int);
findmapc: chan of (Map, chan of int);
dumpmapc: chan of chan of array of Map;


init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	str = load String String->PATH;
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

	regio := sys->file2chan("/chan", "portmapper");
	if(regio == nil)
		fail(sprint("file2chan: %r"));

	delregfidc = chan of int;
	addregc = chan of (ref Reg, chan of string);
	delmapc = chan of (Map, chan of int);
	findmapc = chan of (Map, chan of int);
	dumpmapc = chan of chan of array of Map;

	spawn register(regio);
	spawn listen();
	main();
}

main()
{
	l: list of ref Reg;

Alt:
	for(;;) alt {
	fid := <-delregfidc =>
		nl: list of ref Reg;
		for(; l != nil; l = tl l)
			if((hd l).fid != fid)
				nl = hd l::nl;
		l = nl;

	(reg, errc) := <-addregc =>
		for(t := l; t != nil; t = tl t) {
			r := hd t;
			if(mapsame(r.map, reg.map)) {
				errc <-= "program,version,protocol already registered";
				continue Alt;
			}
		}
		l = reg::l;
		errc <-= nil;

	(map, okc) := <-delmapc =>
		nl: list of ref Reg;
		ok := 0;
		for(; l != nil; l = tl l) {
			e := hd l;
			if(e.map.prog != map.prog || e.map.vers != map.vers)
				nl = e::nl;
			else
				ok = 1;
		}
		l = nl;
		okc <-= ok;

	(map, portc) := <-findmapc =>
		port := 0;
		for(t := l; port == 0 && t != nil; t = tl t)
			if(mapsame((hd t).map, map))
				port = (hd t).map.port;
		portc <-= port;

	mapc := <-dumpmapc =>
		maps := array[len l] of Map;
		i := 0;
		for(t := l; t != nil; t = tl t)
			maps[i++] = (hd t).map;
		mapc <-= maps;
	}
}

mapsame(a, b: Map): int
{
	return a.prog == b.prog
	&& a.vers == b.vers
	&& a.prot == b.prot;
}

register(fio: ref Sys->FileIO)
{
	for(;;) alt {
	(nil, nil, nil, rc) := <-fio.read =>
		if(rc != nil)
			rc <-= (nil, "permission denied");
	(nil, data, fid, rc) := <-fio.write =>
		if(rc == nil) {
			delregfidc <-= fid;
			continue;
		}

		s := string data;
		l := str->unquoted(s);
		if(len l != 5) {
			rc <-= (-1, sprint("bad command, expected 5 words, saw %d words", len l));
			continue;
		}
		if(hd l != "add") {
			rc <-= (-1, sprint("unrecognized command %#q", hd l));
			continue;
		}
		l = tl l;
		
		(prog, rem0) := str->toint(hd l, 10);
		(vers, rem1) := str->toint(hd tl l, 10);
		prot: int;
		protstr := hd tl tl l;
		case protstr {
		"tcp" =>	prot = ProtTcp;
		"udp" =>	prot = ProtUdp;
		* =>
			rc <-= (-1, sprint("unregconized protocol %#q", protstr));
			continue;
		}
		(port, rem2) := str->toint(hd tl tl tl l, 10);
		if(rem0 != nil || rem1 != nil || rem2 != nil) {
			rc <-= (-1, "bad parameters, must be integers");
			continue;
		}
		reg := ref Reg (Map (prog, vers, prot, port), fid);
		addregc <-= (reg, errc := chan of string);
		err := <-errc;
		if(err != nil) {
			rc <-= (-1, "could not register: "+err);
			continue;
		}
		rc <-= (len data, nil);
	}
}

	
listen()
{
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
		addregc <-= (ref Reg (t.map, -1), errc := chan of string);
		err := <-errc;
		r = ref Rportmap.Set (rok, 1);
		if(err != nil) {
			warn("portmap rpc set: "+err);
			r = ref Rportmap.Set (rok, 0);
		}
	Unset =>
		delmapc <-= (t.map, okc := chan of int);
		ok := <-okc;
		if(ok)
			ok = 1;
		r = ref Rportmap.Unset (rok, ok);
	Getport =>
		findmapc <-= (t.map, portc := chan of int);
		port := <-portc;
		r = ref Rportmap.Getport (rok, port);
	Dump =>
		dumpmapc <-= mapc := chan of array of Map;
		maps := <-mapc;
		r = ref Rportmap.Dump (rok, maps);
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
