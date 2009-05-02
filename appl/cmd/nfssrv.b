implement Nfssrv;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, p32, popaque: import sunrpc;
	Parse, Badrpc: import sunrpc;
	Badrpcversion, Badprog, Badproc, Badprocargs: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "../lib/mntrpc.m";
	mntrpc: Mntrpc;
	Tmnt, Rmnt: import mntrpc;
include "../lib/nfsrpc.m";
	nfsrpc: Nfsrpc;
	Tnfs, Rnfs: import nfsrpc;
	Attr, Sattr, Time, Specdata, Weakattr, Weakdata, Dirargs, Nod, Entry, Entryplus: import nfsrpc;
	Rgetattr, Rlookup, Raccess, Rreadlink, Rread, Rwrite, Rchange, Rreaddir, Rreaddirplus, Rfsstat, Rfsinfo, Rpathconf, Rcommit: import nfsrpc;

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
	nfsrpc = load Nfsrpc Nfsrpc->PATH;
	nfsrpc->init();

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

	sys->pctl(Sys->NEWPGRP, nil);

	regfd = sys->open("/chan/portmapper", Sys->OWRITE);
	if(regfd == nil)
		failall(sprint("open /chan/portmapper: %r"));
	if(sys->fprint(regfd, "add %d %d tcp %d\n", mntrpc->ProgMnt, mntrpc->VersMnt, mntport) < 0)
		failall(sprint("registering mnt: %r"));
	if(sys->fprint(regfd, "add %d %d tcp %d\n", nfsrpc->ProgNfs, nfsrpc->VersNfs, nfsport) < 0)
		failall(sprint("registering nfs: %r"));

	spawn listen(nfsport, nfssrv);
	spawn listen(mntport, mntsrv);
}

listen(port: int, srv: ref fn(fd: ref Sys->FD))
{
	addr := sprint("net!*!%d", port);
	(ok, aconn) := sys->announce(addr);
	if(ok < 0)
		failall(sprint("announce %q: %r", addr));
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

mntsrv(fd: ref Sys->FD)
{
	spawn alarm(sys->pctl(0, nil), pidc := chan of int);
	apid := <-pidc;
	for(;;) {
		(buf, err) := sunrpc->readmsg(fd);
		if(err == nil)
			err = mnttransact(buf, nil, fd);
		if(err != nil) {
			warn(err);
			break;
		}
	}
	kill(apid);
}

mnttransact(buf, pre: array of byte, fd: ref Sys->FD): string
{
	say("mnttransact");
	tt: ref Tmnt;
	{
		tt = sunrpc->parsereq(buf, ref Tmnt.Null);
	} exception e {
	Badrpc =>
		r := e.t2;
		warn("mnt, badrpc: "+e.t0);
		return sunrpc->writeresp(fd, pre, pre==nil, r);
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
		say("mnt, null");
		r = ref Rmnt.Null (rok);
	Mnt =>
		say("mnt, mnt eperm");
		fh := array of byte "test";
		auths := array[] of {sunrpc->Anone, sunrpc->Asys};
		r = ref Rmnt.Mnt (rok, Mntrpc->Eok, fh, auths);
	Dump =>
		say("mnt, dump");
		r = ref Rmnt.Dump (rok, nil);
	Umnt =>
		say("mnt, umnt");
		r = ref Rmnt.Umnt (rok);
	Umntall =>
		say("mnt, umntall");
		r = ref Rmnt.Umntall (rok);
	Export =>
		say("mnt, export");
		r = ref Rmnt.Export (rok, nil);
	* =>
		raise "internal error";
	}
	say("have mnt response");
	return sunrpc->writeresp(fd, pre, pre==nil, r);
}


nfssrv(fd: ref Sys->FD)
{
	for(;;) {
		(buf, err) := sunrpc->readmsg(fd);
		if(err == nil)
			err = nfstransact(buf, nil, fd);
		if(err != nil)
			return warn(err);
	}
}

nfstransact(buf, pre: array of byte, fd: ref Sys->FD): string
{
	say("nfstransact");
	tt: ref Tnfs;
	{
		tt = sunrpc->parsereq(buf, ref Tnfs.Null);
	} exception e {
	Badrpc =>
		r := e.t2;
		warn("nfs, bad rpc: "+e.t0);
		return sunrpc->writeresp(fd, pre, pre==nil, r);
	Parse =>
		return "parsing request: "+e;
	}

	say("nfs request: "+tt.text());

	rr: ref Rnfs;
	nullauth: Auth;
	nullauth.which = sunrpc->Anone;
	rok := ref Rrpc.Success  (tt.r.xid, nullauth);
	rbad := ref Rrpc.Systemerr (tt.r.xid, nullauth);
	pick t := tt {
	Null =>
		rr = ref Rnfs.Null;
	Getattr =>
		rr = r := ref Rnfs.Getattr;
		a: Attr;
		a.ftype = nfsrpc->FTdir;
		a.mode = 8r755;
		a.nlink = 1;
		a.uid = a.gid = 0;
		a.size = a.used = big 0;
		a.rdev.major = 0;
		a.rdev.minor = 0;
		a.fsid = big 1;
		a.fileid = big 1;
		a.atime = a.mtime = a.ctime = 0;
		r.r = ref Rgetattr.Ok (a);
	Fsstat =>
		rr = r := ref Rnfs.Fsstat;
		r.r = e := ref Rfsstat.Ok;
		e.attr = nil;
		e.tbytes = big 0;  # total
		e.fbytes = big 0;  # free
		e.abytes = big 0;  # available to user
		e.tfiles = big 0;
		e.ffiles = big 0;
		e.afiles = big 0;
		e.invarsec = 0;
	Fsinfo =>
		rr = r := ref Rnfs.Fsinfo;
		r.r = e := ref Rfsinfo.Ok;
		e.attr = nil;
		e.rtmax = Sys->ATOMICIO;
		e.rtpref = Sys->ATOMICIO;
		e.rtmult = 8;
		e.wtmax = Sys->ATOMICIO;
		e.wtpref = Sys->ATOMICIO;
		e.wtmult = 8;
		e.dtpref = 128;
		e.maxfilesize = big 1<<63;
		e.timedelta.secs = 1;
		e.timedelta.nsecs = 0;
		FSFlink:	con 1<<0;
		FSFsymlink:	con 1<<1;
		FSFhomogeneous:	con 1<<3;
		FSFcansettime:	con 1<<4;
		e.props = FSFhomogeneous|FSFcansettime;
	* =>
		return sunrpc->writeresp(fd, pre, pre==nil, rbad);
		#raise "internal error";
	}
	rr.m = rok;
	say("have mnt response");
	return sunrpc->writeresp(fd, pre, pre==nil, rr);
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
