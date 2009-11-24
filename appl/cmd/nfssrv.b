# nfssrv.
#
# we can run in two modes.  with fhqidpath or with paths.  with fhqidpath,
# file handles are 8 bytes, the qid.path of the files.  with paths,
# we encode the path in the file handle if it fits, otherwise we map
# it to an 8-byte number we keep track of internally (this makes
# nfssrv stateless for larger paths in this mode).
# for fhqidpath, we need two styx fd's: one in which we can open
# qid.path's, and one in which we can open parents of qid.path's.
# without fhqidpath we need one styx fd, the one serving all the
# files.
#
# we can run with or without user/group mapping.  when running
# without, all file operations are done by a single thread, with a
# single mount(2) of the styx file descriptor(s).  when running with
# a user/group mapping, each rpc uid->username gets its own prog to
# do file operations on.  such progs do their mount(s) of the styx
# file descriptor(s), so all operations occur as the user.
#
# file handles are global to all connections, they are just mappings to paths.
# anything with file descriptors cannot be, they must be per-user.

implement Nfssrv;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "string.m";
	str: String;
include "tables.m";
	tables: Tables;
	Table, Strhash: import tables;
include "util0.m";
	util: Util0;
	readfile, writefile, l2a, eq, pid, fail, warn, min, max, hex, index: import util;
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, g64, gopaque, p32, p64, popaque, pstr, pboolopaque, Authsys: import sunrpc;
	Parse, Badrpc: import sunrpc;
	Badrpcversion, Badprog, Badproc, Badprocargs: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "../lib/mntrpc.m";
	mnt: Mntrpc;
	Tmnt, Rmnt, Export: import mnt;
include "../lib/nfsrpc.m";
	nfs: Nfsrpc;
	Tnfs, Rnfs: import nfs;
	Attr, Sattr, Time, Specdata, Weakattr, Weakdata, Dirargs, Nod, Entry, Entryplus, pboolattr: import nfs;
	Rgetattr, Rlookup, Raccess, Rreadlink, Rread, Rwrite, Rchange, Rreaddir, Rreaddirplus, Rfsstat, Rfsinfo, Rpathconf, Rcommit: import nfs;

Nfssrv: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};


Dh: adt {
	fd:	ref Sys->FD;
	dirs:	array of Sys->Dir;
	off:	int;	# dirs starts at off, first is 1 , to let cookie 0 be special
	verf:	big;
	use:	int;	# last use
	busy:	int;	# whether handed out by main()
};

# for plain files only
Fd: adt {
	fh:	array of byte;
	mode:	int;	# OREAD or OWRITE
	fd:	ref Sys->FD;
	use:	int;	# last use
};

Srv: adt {
	uid:	int;
	uname:	string;
	srvpid:	int;
	mgrpid:	int;

	nfsc:	chan of (ref Tnfs, chan of ref Rnfs);
	mntc:	chan of (ref Tmnt, chan of ref Rmnt);

	cleanpid:	int;
	fdcache:	list of ref Fd;
	dirhandles:	list of ref Dh;

	cleanc:		chan of int;
	finddirc:	chan of (array of byte, big, int, chan of (ref Dh, ref Attr, int));
	dirc:		chan of ref Dh;
	newdirc:	chan of ref Dh;
	fdopenc:	chan of (array of byte, string, int, chan of (ref Sys->FD, string));
};

dflag: int;

nfsport := 2049;
mntport := 39422;
protocol: string;  # nil is both tcp & udp, otherwise it's the protocol specified
regfd: ref Sys->FD;  # global, so we keep a reference until nfssrv dies
timefd: ref Sys->FD;
defuser: string;	# fallback user to execute nfs/mnt operations as

styxfd: ref Sys->FD;

# for fhqidpath mode
qidpathaname,
qidpathanameup,
pathstyxmtpt,
pathstyxupmtpt: string;
rootqidpath: big;
fhqidpath: int;

uidsrv: ref Table[ref Srv];
defsrv: ref Srv; # used when without user/group file

Int: adt {
	v:	int;
};
userfile,
groupfile:	string;
uids,
gids: ref Table[string];
users,
groups:	ref Strhash[ref Int];

Fh: adt {
	fh:	big;
	path:	string;
	use:	int;	# last use
};
fhgen := big 1;
filehandles: list of ref Fh;

uidc: chan of (int, chan of ref Srv);
cleanc: chan of int;
fhfindc: chan of (big, chan of ref Fh);
fhgetpathc: chan of (string, chan of ref Fh);

nilwd: Weakdata;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	str = load String String->PATH;
	tables = load Tables Tables->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	mnt = load Mntrpc Mntrpc->PATH;
	mnt ->init();
	nfs = load Nfsrpc Nfsrpc->PATH;
	nfs->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] [-n nfsport] [-m mntport] [-p udp|tcp] [-t passwd group] [-s aname anameup mtpt mtptup rootqidpath] styxfile");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		'n' =>	nfsport = int arg->earg();
		'm' =>	mntport = int arg->earg();
		'p' =>
			case protocol = arg->earg() {
			"udp" or
			"tcp" =>
				;
			* =>
				arg->usage();
			}
		's' =>
			qidpathaname = arg->earg();
			qidpathanameup = arg->earg();
			pathstyxmtpt = arg->earg();
			pathstyxupmtpt = arg->earg();
			rootqidpath = str->tobig(arg->earg(), 16).t0;
			fhqidpath = 1;
		't' =>
			userfile = arg->earg();
			groupfile = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();

	sys->pctl(Sys->NEWPGRP, nil);

	defuserbuf := readfile("/dev/user", -1);
	if(len defuserbuf == 0)
		fail(sprint("/dev/user: %r"));
	defuser = string defuserbuf;
	say(sprint("defuser: %q", defuser));

	timefd = sys->open("/dev/time", Sys->OREAD);
	if(timefd == nil)
		fail(sprint("open /dev/time: %r"));

	f := hd args;
	styxfd = sys->open(f, Sys->ORDWR);
	if(styxfd == nil)
		fail(sprint("open %q: %r", f));

	sunrpc->dflag = max(0, dflag-2);
	mnt->dflag = max(0, dflag-1);
	nfs->dflag = max(0, dflag-1);

	if(userfile == nil) {
		defsrv = startsrv(0, defuser);
		if(defsrv == nil)
			failall("starting default srv failed");
	} else
		uidsrv = uidsrv.new(31, nil);

	if(userfile != nil) {
		uids = uids.new(31, nil);
		users = users.new(31, nil);
		readpasswd(userfile);
		defuser = "none";
	}
	if(groupfile != nil) {
		gids = gids.new(31, nil);
		groups = groups.new(31, nil);
		readgroup(groupfile);
	}

	regfd = sys->open("/chan/portmapper", Sys->OWRITE);
	if(regfd == nil)
		failall(sprint("open /chan/portmapper: %r"));
	if(protocol != "udp" && sys->fprint(regfd, "add %d %d tcp %d\n", mnt->ProgMnt, mnt->VersMnt, mntport) < 0)
		failall(sprint("registering mnt tcp: %r"));
	if(protocol != "tcp" && sys->fprint(regfd, "add %d %d udp %d\n", mnt->ProgMnt, mnt->VersMnt, mntport) < 0)
		failall(sprint("registering mnt udp: %r"));
	if(protocol != "udp" && sys->fprint(regfd, "add %d %d tcp %d\n", nfs->ProgNfs, nfs->VersNfs, nfsport) < 0)
		failall(sprint("registering nfs tcp: %r"));
	if(protocol != "tcp" && sys->fprint(regfd, "add %d %d udp %d\n", nfs->ProgNfs, nfs->VersNfs, nfsport) < 0)
		failall(sprint("registering nfs udp: %r"));

	uidc = chan of (int, chan of ref Srv);
	cleanc = chan of int;
	fhfindc = chan of (big, chan of ref Fh);
	fhgetpathc = chan of (string, chan of ref Fh);

	if(protocol != "udp") {
		spawn listen(nfsport, nfssrv);
		spawn listen(mntport, mntsrv);
	}
	if(protocol != "tcp") {
		spawn listenudp(nfsport, nfstransact);
		spawn listenudp(mntport, mnttransact);
	}
	spawn main();
}

startsrv(uid: int, name: string): ref Srv
{
	nfsc := chan of (ref Tnfs, chan of ref Rnfs);
	mntc := chan of (ref Tmnt, chan of ref Rmnt);

	finddirc := chan of (array of byte, big, int, chan of (ref Dh, ref Attr, int));
	dirc := chan of ref Dh;
	newdirc := chan of ref Dh;
	fdopenc := chan of (array of byte, string, int, chan of (ref Sys->FD, string));

	srv := ref Srv (uid, name, -1, -1, nfsc, mntc, -1, nil, nil, chan of int, finddirc, dirc, newdirc, fdopenc);

	spawn startsrv0(srv, okc := chan of int);
	ok := <-okc;
	if(!ok)
		return nil;
	return srv;
}

startsrv0(srv: ref Srv, okc: chan of int)
{
	if(dflag) say(sprint("startsrv0, for name %#q", srv.uname));
	err := writefile("/dev/user", 0, array of byte srv.uname);
	if(err != nil) {
		warn(sprint("srv, writing %#q to /dev/user: %r", srv.uname));
		okc <-= 0;
		return;
	}
	sys->pctl(Sys->NEWNS, nil);
	sys->chdir("/");
	if(fhqidpath) {
		r0 := sys->mount(styxfd, nil, pathstyxmtpt, Sys->MREPL, qidpathaname);
		if(r0 < 0 || sys->mount(styxfd, nil, pathstyxupmtpt, Sys->MREPL, qidpathanameup) < 0) {
			warn(sprint("srv, mounts for user %#q: %r", srv.uname));
			okc <-= 0;
			return;
		}
	} else {
		if(sys->mount(styxfd, nil, "/", Sys->MREPL|Sys->MCREATE, nil) < 0) {
			warn(sprint("srv, mount for user %#q: %r", srv.uname));
			okc <-= 0;
			return;
		}
	}

	spawn srv0(srv, pidc := chan of int);
	srv.srvpid = <-pidc;
	spawn mgr(srv, pidc);
	srv.mgrpid = <-pidc;
	okc <-= 1;
}

srv0(srv: ref Srv, pidc: chan of int)
{
	pidc <-= pid();
	for(;;) alt {
	(t, rc) := <-srv.mntc =>
		rc <-= mntexec(t);

	(t, rc) := <-srv.nfsc =>
		rc <-= nfsexec(srv, t);
	}
}

uid2name(uid: int): string
{
	if(uids == nil)
		return defuser;
	s := uids.find(uid);
	if(s == nil)
		s = "none";
	return s;
}

name2uid(name: string): int
{
	if(users == nil)
		return 0;
	s := users.find(name);
	if(s == nil)
		return 0;
	return s.v;
}

gid2name(gid: int): string
{
	if(gids == nil)
		return defuser;
	s := gids.find(gid);
	if(s == nil)
		s = "none";
	return s;
}

name2gid(name: string): int
{
	if(groups == nil)
		return 0;
	s := groups.find(name);
	if(s == nil)
		return 0;
	return s.v;
}

readpasswd(f: string)
{
	b := bufio->open(f, Bufio->OREAD);
	if(b == nil)
		fail(sprint("open %q: %r", f));
	nl := 0;
	for(;;) {
		s := b.gets('\n');
		if(s == nil)
			break;
		nl++;
		if(s[len s-1] != '\n')
			fail(sprint("%q:%d: missing newline at end of file", f, nl));
		s = s[:len s-1];
		t := l2a(sys->tokenize(s, ":").t1);
		if(len t < 4)
			fail(sprint("%q:%d: too few tokens", f, nl));
		(uid, urem) := str->toint(t[2], 10);
		(gid, grem) := str->toint(t[3], 10);
		if(urem != nil || grem != nil)
			fail(sprint("%q:%d: bad uid/gid", f, nl));
		user := t[0];
		uids.add(uid, user);
		users.add(user, ref Int (uid));
		gid = 0; # not using gid for now...
	}
}

readgroup(f: string)
{
	b := bufio->open(f, Bufio->OREAD);
	if(b == nil)
		fail(sprint("open %q: %r", f));
	nl := 0;
	for(;;) {
		s := b.gets('\n');
		if(s == nil)
			break;
		nl++;
		if(s[len s-1] != '\n')
			fail(sprint("%q:%d: missing newline at end of file", f, nl));
		s = s[:len s-1];
		t := l2a(sys->tokenize(s, ":").t1);
		if(len t < 3)
			fail(sprint("%q:%d: too few tokens", f, nl));
		(gid, grem) := str->toint(t[2], 10);
		if(grem != nil)
			fail(sprint("%q:%d: bad gid", f, nl));
		group := t[0];
		gids.add(gid, group);
		groups.add(group, ref Int (gid));
	}
}

listen(port: int, srv: ref fn(fd: ref Sys->FD))
{
	addr := sprint("net!*!%d", port);
	(ok, aconn) := sys->announce(addr);
	if(ok < 0)
		failall(sprint("announce %q: %r", addr));
	say("announced tcp");
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

listenudp(port: int, transact: ref fn(buf, pre: array of byte, fd: ref Sys->FD): string)
{
	addr := sprint("udp!*!%d", port);
	(ok, c) := sys->announce(addr);
	if(ok < 0)
		fail(sprint("announce %q: %r", addr));
	if(sys->fprint(c.cfd, "headers") < 0)
		fail(sprint("udp ctl 'headers': %r"));
	fd := sys->open(c.dir+"/data", Sys->ORDWR);
	if(fd == nil)
		fail(sprint("udp data: %r"));
	say("announced udp");
	buf := array[52+64*1024] of byte;
	for(;;) {
		n := sys->read(fd, buf, len buf);
		if(n < 0)
			fail(sprint("udp read: %r"));
		if(n < 52)
			fail(sprint("short udp read, length %d < 52", n));
		err := transact(buf[52:n], buf[:52], fd);
		if(err != nil)
			say(err);
	}
}


alarm(apid: int, pidc: chan of int)
{
	pidc <-= pid();
	sys->sleep(10*1000);
	kill(apid);
}

mntsrv(fd: ref Sys->FD)
{
	spawn alarm(pid(), pidc := chan of int);
	apid := <-pidc;
	for(;;) {
		(buf, err) := sunrpc->readmsg(fd);
		if(err == nil)
			err = mnttransact(buf, nil, fd);
		if(err != nil) {
			say(err);
			break;
		}
	}
	kill(apid);
}

mnttransact(buf, pre: array of byte, fd: ref Sys->FD): string
{
	if(dflag) say("mnttransact");
	as: ref Authsys;
	tt: ref Tmnt;
	{
		tt = sunrpc->parsereq(buf, ref Tmnt.Null);
		if(tt.r.cred.which == sunrpc->Asys)
			as = Authsys.unpack(tt.r.cred.buf, 0);

	} exception e {
	Badrpc =>
		r := e.t2;
		say("mnt, badrpc: "+e.t0);
		return sunrpc->writerpc(fd, pre, pre==nil, r);
	Parse =>
		return "parsing request: "+e;
	}

	if(tagof tt != tagof Tnfs.Null && as == nil) {
		rbadauth := ref Rrpc.Autherror (tt.r.xid, sunrpc->AUtooweak);
		return sunrpc->writerpc(fd, pre, pre==nil, rbadauth);
	}

	srv := defsrv;
	if(srv == nil) {
		uidc <-= (as.uid, rc := chan of ref Srv);
		srv = <-rc;
		if(srv == nil) {
			rbadauth := ref Rrpc.Autherror (tt.r.xid, sunrpc->AUrejectedcred);
			return sunrpc->writerpc(fd, pre, pre==nil, rbadauth);
		}
	}

	srv.mntc <-= (tt, rc := chan of ref Rmnt);
	r := <-rc;
	return sunrpc->writerpc(fd, pre, pre==nil, r);
}

mntexec(tt: ref Tmnt): ref Rmnt
{
	r: ref Rmnt;
	nullauth: Auth;
	nullauth.which = sunrpc->Anone;
	rok := ref Rrpc.Success (tt.r.xid, nullauth);
	pick t := tt {
	Null =>
		say("mnt, null");
		r = ref Rmnt.Null (rok);
	Mnt =>
		say("mnt, mnt");
		status := Mntrpc->Eok;
		fh := path2fh(t.dirpath);
		if(fh == nil)
			status = errno();
		auths := array[] of {sunrpc->Asys};
		r = ref Rmnt.Mnt (rok, status, fh, auths);
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
		exports := array[] of {Export ("/", array[] of {"all"})};
		r = ref Rmnt.Export (rok, exports);
	* =>
		raise "internal error";
	}
	return r;
}

nfssrv(fd: ref Sys->FD)
{
	for(;;) {
		(buf, err) := sunrpc->readmsg(fd);
		if(err == nil)
			err = nfstransact(buf, nil, fd);
		if(err != nil)
			return say(err);
	}
}

nfstransact(buf, pre: array of byte, fd: ref Sys->FD): string
{
	as: ref Authsys;
	tt: ref Tnfs;
	{
		tt = sunrpc->parsereq(buf, ref Tnfs.Null);
		if(tt.r.cred.which == sunrpc->Asys)
			as = Authsys.unpack(tt.r.cred.buf, 0);
	} exception e {
	Badrpc =>
		r := e.t2;
		say("nfs, bad rpc: "+e.t0);
		return sunrpc->writerpc(fd, pre, pre==nil, r);
	Parse =>
		return "parsing request: "+e;
	}

	if(tagof tt != tagof Tnfs.Null && as == nil) {
		rbadauth := ref Rrpc.Autherror (tt.r.xid, sunrpc->AUtooweak);
		return sunrpc->writerpc(fd, pre, pre==nil, rbadauth);
	}

	srv := defsrv;
	if(srv == nil) {
		uidc <-= (as.uid, rc := chan of ref Srv);
		srv = <-rc;
		if(srv == nil) {
			rbadauth := ref Rrpc.Autherror (tt.r.xid, sunrpc->AUrejectedcred);
			return sunrpc->writerpc(fd, pre, pre==nil, rbadauth);
		}
	}
	srv.nfsc <-= (tt, rc := chan of ref Rnfs);
	r := <-rc;
	return sunrpc->writerpc(fd, pre, pre==nil, r);
}

nfsexec(srv: ref Srv, tt: ref Tnfs): ref Rnfs
{
	rr: ref Rnfs;
	nullauth: Auth;
	nullauth.which = sunrpc->Anone;
	rok := ref Rrpc.Success  (tt.r.xid, nullauth);
Top:
	pick t := tt {
	Null =>
		rr = ref Rnfs.Null;

	Getattr =>
		rr = r := ref Rnfs.Getattr;
		(ok, dir) := fhstat(t.fh);
		if(ok == 0)
			r.r = ref Rgetattr.Ok (dir2attr(dir));
		else
			r.r = ref Rgetattr.Fail (errno());

	Setattr =>
		rr = r := ref Rnfs.Setattr;
		r.weak = nilwd;

		(ok, dir) := fhstat(t.fh);
		if(ok < 0) {
			r.status = errno();
			break;
		}
		if(t.haveguard && dir.mtime != t.guardctime) {
			r.status = nfs->Enotsync;
			break;
		}

		# build the new Dir, starting with all don't cares.
		# "bad" indicates whether we encountered a request we don't supported.
		(ndir, bad) := sattr2dir(t.newattr, dir.mode);
		if(bad)
			r.status = nfs->Einval;
		else if(fhwstat(t.fh, ndir) < 0)
			r.status = errno();
		else
			r.status = nfs->Eok;

	Lookup =>
		rr = r := ref Rnfs.Lookup;
		fh := fhlookup(t.where.fh, t.where.name);
		if(fh == nil)
			r.r = ref Rlookup.Fail (errno(), nil);
		else
			r.r = ref Rlookup.Ok (fh, fhattr(fh), fhattr(t.where.fh));

	Access =>
		rr = r := ref Rnfs.Access;
		(ok, dir) := fhstat(t.fh);
		if(ok < 0) {
			r.r = ref Raccess.Fail (errno(), nil);
			break;
		}

		# only an approximation, actual operations will show the truth.
		access := 0;
		perm: int;
		if(dir.uid == srv.uname)
			perm = dir.mode>>6;
		else if(dir.gid == srv.uname)
			perm = dir.mode>>3;
		else
			perm = dir.mode;
		perm &= 8r7;
		br := bw := bx := 0;
		if(perm&8r4) br = ~0;
		if(perm&8r2) bw = ~0;
		if(perm&8r1) bx = ~0;
		if(dflag) say(sprint("mode 8r%uo, uid %q gid %q uname %q, perm 8r%uo", dir.mode, dir.uid, dir.gid, srv.uname, perm));
		if(dflag) say(sprint("perm 8r%uo, br %ux bw %ux bx %ux", perm, br, bw, bx));
		access |= nfs->ACread&br;
		access |= (nfs->ACmodify|nfs->ACextend|nfs->ACdelete)&bw;
		access |= (nfs->AClookup|nfs->ACexecute)&bx;
		r.r = ref Raccess.Ok (ref dir2attr(dir), access);

	Readlink =>
		rr = r := ref Rnfs.Readlink;
		r.r = ref Rreadlink.Fail (nfs->Enotsupp, nil);

	Read =>
		rr = r := ref Rnfs.Read;
		ffd := fhopen(srv, t.fh, Sys->OREAD, 1);
		if(ffd == nil || (n := sys->pread(ffd, rbuf := array[min(t.count, Sys->ATOMICIO)] of byte, len rbuf, t.offset)) < 0)
			r.r = ref Rread.Fail (errno(), nil);
		else {
			(ok, dir) := sys->fstat(ffd);
			if(ok == 0)
				attr := ref dir2attr(dir);
			eof := n==0;
			r.r = ref Rread.Ok (attr, n, eof, rbuf[:n]);
		}

	Write =>
		rr = r := ref Rnfs.Write;
		ffd := fhopen(srv, t.fh, Sys->OWRITE, 1);
		if(ffd == nil || sys->pwrite(ffd, t.data, len t.data, t.offset) != len t.data) {
			r.r = ref Rwrite.Fail (errno(), nilwd);
			break;
		}
		how := t.stablehow;
		case t.stablehow {
		nfs->WriteUnstable =>
			;
		nfs->WriteDatasync or
		nfs->WriteFilesync =>
			if(fhwstat(t.fh, sys->nulldir) < 0) {
				r.r = ref Rwrite.Fail (errno(), nilwd);
				break Top;
			}
			how = nfs->WriteFilesync;
		* =>
			raise "missing case";
		}
		r.r = ref Rwrite.Ok (nilwd, len t.data, how, verifier(ffd));

	Create =>
		rr = r := ref Rnfs.Create;
		r.r = e := ref Rchange.Fail;
		e.weak = nilwd;

		mode := Sys->OREAD;
		perm := 8r777;
		pick c := t.createhow {
		Unchecked =>
			if(c.attr.setmode)
				perm = c.attr.mode&8r777;
		Guarded =>
			if(c.attr.setmode)
				perm = c.attr.mode&8r777;
			mode |= Sys->OEXCL;
		Exclusive =>
			mode |= Sys->OEXCL;
		}
		fh := fhcreate(t.where.fh, t.where.name, mode, perm);
		if(fh == nil) {
			e.status = errno();
			break;
		}
		# xxx wstat ?
		r.r = ref Rchange.Ok (fh, fhattr(fh), nilwd);

	Mkdir =>
		rr = r := ref Rnfs.Mkdir;
		r.r = e := ref Rchange.Fail;
		e.weak = nilwd;

		perm := 8r777;
		if(t.attr.setmode)
			perm = t.attr.mode&8r777;
		fh := fhcreate(t.where.fh, t.where.name, Sys->OREAD, Sys->DMDIR|perm);
		if(fh == nil) {
			e.status = errno();
			break;
		}

		t.attr.setmode = 0;
		# could skip fhwstat when remaining t.attr is nulldir...
		(ndir, bad) := sattr2dir(t.attr, 0);
		if(bad)
			e.status = nfs->Einval;
		else if(fhwstat(fh, ndir) < 0)
			e.status = errno();
		else
			r.r = ref Rchange.Ok (fh, fhattr(fh), nilwd);

	Symlink =>
		rr = r := ref Rnfs.Symlink;
		r.r = ref Rchange.Fail (nfs->Enotsupp, nilwd);

	Mknod =>
		rr = r := ref Rnfs.Mknod;
		r.r = ref Rchange.Fail (nfs->Enotsupp, nilwd);

	Remove =>
		rr = r := ref Rnfs.Remove;
		r.weak = nilwd;
		fh := fhlookup(t.where.fh, t.where.name);
		if(fh != nil)
			path := fhpath(fh);
		if(path == nil || sys->remove(path) < 0)
			r.status = errno();
		else
			r.status = nfs->Eok;

	Rmdir =>
		rr = r := ref Rnfs.Rmdir;
		r.weak = nilwd;
		fh := fhlookup(t.where.fh, t.where.name);
		if(fh != nil)
			path := fhpath(fh);
		if(path == nil || sys->remove(path) < 0)
			r.status = errno();
		else
			r.status = nfs->Eok;

	Rename =>
		rr = r := ref Rnfs.Rename;
		r.fromdir = nilwd;
		r.todir = nilwd;

		if(t.owhere.fh != t.nwhere.fh || badname(t.nwhere.name)) {
			r.status = nfs->Einval;
			break;
		}
		ndir := sys->nulldir;
		ndir.name = t.nwhere.name;
		fh := fhlookup(t.owhere.fh, t.owhere.name);
		if(fh == nil || fhwstat(fh, ndir) < 0)
			r.status = errno();
		else
			r.status = nfs->Eok;

	Link =>
		rr = ref Rnfs.Link (nil, nfs->Enotsupp, nil, nilwd);

	Readdir =>
		rr = r := ref Rnfs.Readdir;
		(dh, attr, status) := dirget(srv, t.fh, t.cookieverf, t.cookie);
		if(dh == nil) {
			r.r = ref Rreaddir.Fail (status, nil);
			break;
		}

		eof := 0;
		entries: list of Entry;
		cookie := int t.cookie;
		rsize := pboolattr(nil, 0, attr)+8+4+4; # attributes, cookieverf, 0 entries, eof
		for(;;) {
			(ok, ncookie, dir) := dirnext(dh, cookie);
			if(ok < 0) {
				r.r = ref Rreaddir.Fail (errno(), nil);
				dirput(srv, dh);
				break Top;
			}
			if(ncookie < 0) {
				eof = 1;
				break;
			}
			e := Entry (dir.qid.path, dir.name, big ncookie);
			esize := entrysize(e);
			if(rsize+esize > t.count)
				break;
			rsize += esize;
			entries = e::entries;
			cookie = ncookie;
		}
		ents := array[len entries] of Entry;
		i := len entries-1;
		for(; entries != nil; entries = tl entries)
			ents[i--] = hd entries;
		r.r = ref Rreaddir.Ok (attr, dh.verf, ents, eof);
		dirput(srv, dh);

	Readdirplus =>
		rr = r := ref Rnfs.Readdirplus;

		(dh, attr, status) := dirget(srv, t.fh, t.cookieverf, t.cookie);
		if(dh == nil) {
			r.r = ref Rreaddirplus.Fail (status, nil);
			break;
		}

		eof := 0;
		entries: list of Entryplus;
		cookie := int t.cookie;
		rsize := pboolattr(nil, 0, attr)+8+4+4; # attr+cookieverf+0 entries+eof
		dsize := 0;
		for(;;) {
			(ok, ncookie, dir) := dirnext(dh, cookie);
			if(ok < 0) {
				r.r = ref Rreaddirplus.Fail (errno(), nil);
				dirput(srv, dh);
				break Top;
			}
			if(ncookie < 0) {
				eof = 1;
				break;
			}

			# xxx have to verify this after i have more stuff working...
			# sending a file handle for each entryplus seems superfluous.
			# but linux' in-kernel nfs client seems to treat absent file handles as zero-length file handles,
			# so include a file handle to help linux clients.
			e := Entryplus (dir.qid.path, dir.name, big ncookie, ref dir2attr(dir), fhlookupdir(t.fh, dir));
			esize0 := entryplussize(e, 0);
			esize1 := entryplussize(e, 1);
			if(rsize+esize1 >= t.maxcount || dsize+esize0 >= t.dircount)
				break;
			rsize += esize1;
			dsize += esize0;
			entries = e::entries;
			cookie = ncookie;
		}
		ents := array[len entries] of Entryplus;
		i := len entries-1;
		for(; entries != nil; entries = tl entries)
			ents[i--] = hd entries;
		r.r = ref Rreaddirplus.Ok (attr, dh.verf, ents, eof);
		dirput(srv, dh);

	Fsstat =>
		rr = r := ref Rnfs.Fsstat;
		r.r = e := ref Rfsstat.Ok;
		e.attr = fhattr(t.rootfh);
		if(e.attr == nil) {
			r.r = ref Rfsstat.Fail (errno(), nil);
			break;
		}
		e.tbytes = big 0;  # total
		e.fbytes = big 0;  # free
		e.abytes = big 0;  # available to user
		e.tfiles = big 0;  # same, but "inodes"
		e.ffiles = big 0;
		e.afiles = big 0;
		e.invarsec = 0;

	Fsinfo =>
		rr = r := ref Rnfs.Fsinfo;
		r.r = e := ref Rfsinfo.Ok;
		e.attr = fhattr(t.rootfh);
		if(e.attr == nil) {
			r.r = ref Rfsinfo.Fail (errno(), nil);
			break;
		}
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
		e.props = nfs->FSFhomogeneous|nfs->FSFcansettime;

	Pathconf =>
		rr = r := ref Rnfs.Pathconf;
		(ok, dir) := fhstat(t.fh);
		if(ok != 0) {
			r.r = ref Rpathconf.Fail (errno(), nil);
			break;
		}
		e := r.r = ref Rpathconf.Ok;
		e.attr = ref dir2attr(dir);
		e.linkmax = 1;
		e.namemax = 1024;
		e.notrunc = 1;
		e.chownrestr = 1;
		e.caseinsens = 0;
		e.casepres = 1;

	Commit =>
		rr = r := ref Rnfs.Commit;
		if(fhwstat(t.fh, sys->nulldir) < 0)
			r.r = ref Rcommit.Fail (errno(), nilwd);
		else
			r.r = ref Rcommit.Ok (nilwd, fhverifier(t.fh));

	* =>
		raise "internal error";
	}
	rr.m = rok;
	return rr;
}

dirget(srv: ref Srv, fh: array of byte, verf, bcookie: big): (ref Dh, ref Attr, int)
{
	last := int bcookie;
	if(bcookie != big last)
		return (nil, nil, nfs->Ebadcookie);

	rc := chan of (ref Dh, ref Attr, int);
	srv.finddirc <-= (fh, verf, last, rc);
	return <-rc;
}

dirput(srv: ref Srv, dh: ref Dh)
{
	srv.dirc <-= dh;
}

cleanpid := -1;
main()
{
	for(;;) alt {
	(uid, rc) := <-uidc =>
		srv := uidsrv.find(uid);
		if(srv == nil) {
			name := uid2name(uid);
			srv = startsrv(uid, name);
			if(srv != nil)
				uidsrv.add(uid, srv);
		}
		rc <-= srv;

	<-cleanc =>
		# clean up file handles with last use >300 seconds ago.
		fr: list of ref Fh;
		fhold := now()-300;
		for(fl := filehandles; fl != nil; fl = tl fl) {
			fh := hd fl;
			if(fh.use >= fhold)
				fr = fh::fr;
		}
		filehandles = fr;
		if(filehandles == nil) {
			kill(cleanpid);
			cleanpid = -1;
		}

	(v, rc) := <-fhfindc =>
		f: ref Fh;
		for(l := filehandles; l != nil; l = tl l)
			if((hd l).fh == v) {
				f = hd l;
				f.use = now();
				break;
			}
		rc <-= f;

	(path, rc) := <-fhgetpathc =>
		f: ref Fh;
		for(l := filehandles; l != nil; l = tl l)
			if((hd l).path == path) {
				f = hd l;
				f.use = now();
				break;
			}
		if(f == nil) {
			f = ref Fh (fhgen++, path, now());
			filehandles = f::filehandles;
			if(cleanpid < 0) {
				spawn cleaner(cleanc, pidc := chan of int);
				cleanpid = <-pidc;
			}
		}
		rc <-= f;
	}
}

mgr(srv: ref Srv, mpidc: chan of int)
{
	mpidc <-= pid();

loop:
	for(;;) alt {
	<-srv.cleanc =>
		# clean up dirs that are not busy and last use was >90 seconds ago.
		dr: list of ref Dh;
		dhold := now()-90;
		for(dl := srv.dirhandles; dl != nil; dl = tl dl) {
			dh := hd dl;
			if(dh.busy || dh.use >= dhold)
				dr = dh::dr;
		}
		srv.dirhandles = dr;

		# clean up fd's with last use >15 seconds ago
		fdr: list of ref Fd;
		fdold := now()-15;
		for(fdl := srv.fdcache; fdl != nil; fdl = tl fdl) {
			fd := hd fdl;
			if(fd.use >= fdold)
				fdr = fd::fdr;
		}
		srv.fdcache = fdr;

		if(srv.dirhandles == nil && srv.fdcache == nil) {
			kill(srv.cleanpid);
			srv.cleanpid = -1;
		}

	(fh, verf, last, rc) := <-srv.finddirc =>
		# find by verf,cookie
		if(last != 0)
		for(l := srv.dirhandles; l != nil; l = tl l) {
			dh := hd l;
			if(dh.busy || dh.verf != verf || !dirhas(dh, last))
				continue;

			(ok, dir) := sys->fstat(dh.fd);
			if(ok != 0 || dir2verifier(dir) != verf) {
				rc <-= (nil, nil, nfs->Ebadcookie);
			} else {
				dh.use = now();
				dh.busy = 1;
				rc <-= (dh, ref dir2attr(dir), 0);
			}
			continue loop;
		}

		# init new dh
		spawn newdir(srv, fh, verf, last, rc);

	dh := <-srv.newdirc =>
		srv.dirhandles = dh::srv.dirhandles;
		if(srv.cleanpid < 0) {
			spawn cleaner(srv.cleanc, pidc := chan of int);
			srv.cleanpid = <-pidc;
		}

	dh := <-srv.dirc =>
		if(!dh.busy)
			raise "not busy?";
		dh.busy = 0;

	(fh, path, mode, rc) := <-srv.fdopenc =>
		for(l := srv.fdcache; l != nil; l = tl l) {
			f := hd l;
			if(f.mode == mode && eq(fh, f.fh)) {
				f.use = now();
				rc <-= (f.fd, nil);
				continue loop;
			}
		}

		fd := sys->open(path, mode);
		if(fd == nil) {
			rc <-= (nil, sprint("%r"));
		} else {
			rc <-= (fd, nil);
			f := ref Fd (fh, mode, fd, now());
			srv.fdcache = f::srv.fdcache;
			if(srv.cleanpid < 0) {
				spawn cleaner(srv.cleanc, pidc := chan of int);
				srv.cleanpid = <-pidc;
			}
		}
	}
}

cleaner(rc: chan of int, pidc: chan of int)
{
	pidc <-= pid();
	for(;;) {
		sys->sleep(10*1000);
		rc <-= 1;
	}
}

newdir(srv: ref Srv, fh: array of byte, verf: big, cookie: int, rc: chan of (ref Dh, ref Attr, int))
{
	(dh, attr, status) := newdir0(srv, fh, verf, cookie);
	if(dh != nil) {
		dh.busy = 1;
		dh.use = now();
		srv.newdirc <-= dh;
	}
	rc <-= (dh, attr, status);
}

newdir0(srv: ref Srv, fh: array of byte, verf: big, last: int): (ref Dh, ref Attr, int)
{
	fd := fhopen(srv, fh, Sys->OREAD, 0);
	if(fd == nil)
		return (nil, nil, errno());
	(ok, dir) := sys->fstat(fd);
	if(ok != 0)
		return (nil, nil, errno());
	nverf := dir2verifier(dir);
	if(verf != big 0 && verf != nverf)
		return (nil, nil, nfs->Ebadcookie);

	dh := ref Dh (fd, nil, 1, nverf, now(), 0);
	next := last+1;
	while(next > dh.off+len dh.dirs) {
		(n, dirs) := sys->dirread(dh.fd);
		if(n < 0)
			return (nil, nil, errno());
		if(n == 0)
			return (nil, nil, nfs->Ebadcookie);
		dh.off += len dh.dirs;
		dh.dirs = dirs;
	}

	return (dh, ref dir2attr(dir), 0);
}

# whether Dh has the last (offset) or next one to read will be it
dirhas(dh: ref Dh, last: int): int
{
	return last >= dh.off && last <= dh.off+len dh.dirs;
}

dirnext(dh: ref Dh, last: int): (int, int, Sys->Dir)
{
	next := last+1;
	if(next == dh.off+len dh.dirs) {
		(n, dirs) := sys->dirread(dh.fd);
		if(n <= 0)
			return (n, -1, sys->zerodir);
		dh.off += len dh.dirs;
		dh.dirs = dirs;
	}
	return (0, next, dh.dirs[next-dh.off]);
}

fhfind(v: big): ref Fh
{
	if(fhqidpath)
		raise "fhfind with fhqidpath";
	fhfindc <-= (v, rc := chan of ref Fh);
	return <-rc;
}

fhgetpath(path: string): ref Fh
{
	if(fhqidpath)
		raise "fhfindpath with fhqidpath";
	fhgetpathc <-= (path, rc := chan of ref Fh);
	return <-rc;
}

fhbuf(v: big): array of byte
{
	buf := array[8] of byte;
	p64(buf, 0, v);
	return buf;
}

fhpathbuf(buf: array of byte): array of byte
{
	if(1+len buf > nfs->Filehandlesizemax)
		raise "bad buf";
	fh := array[1+len buf] of byte;
	fh[0] = ~byte 0;
	fh[1:] = buf;
	return fh;
}

fhputpath(path: string): array of byte
{
	buf := array of byte path;
	if(1+len buf <= nfs->Filehandlesizemax)
		return fhpathbuf(buf);

	f := fhgetpath(path);
	return fhbuf(f.fh);
}

path2fh(path: string): array of byte
{
	if(fhqidpath) {
		p := sprint("%s/%bux/%s", pathstyxmtpt, rootqidpath, path);
		(ok, dir) := sys->stat(p);
		if(ok != 0)
			return nil;
		return fhbuf(dir.qid.path);
	}

	if(path != "/") {
		sys->werrstr(Eperm);
		return nil;
	}
	buf := array of byte path;
	if(1+len path > nfs->Filehandlesizemax)
		return nil;	# not supported
	return fhpathbuf(buf);
}

fhpath(fh: array of byte): string
{
	if(len fh == 0) {
		sys->werrstr(Ebadarg);
		return nil;
	}
	if(fhqidpath) {
		if(len fh != 8) {
			sys->werrstr(Ebadarg);
			return nil;
		}
		return sprint("%s/%bux", pathstyxmtpt, g64(fh, 0).t0);
	}

	if(fh[0] == ~byte 0)
		return string fh[1:];

	if(len fh != 8) {
		sys->werrstr(Ebadarg);
		return nil;
	}
	f := fhfind(g64(fh, 0).t0);
	if(f == nil)
		return nil;
	return f.path;
}

fhlookup(fh: array of byte, name: string): array of byte
{
	if(name == "" || len fh == 0) {
		sys->werrstr(Ebadarg);
		return nil;
	}
	if(name == ".")
		return fh;

	if(fhqidpath) {
		if(len fh != 8) {
			sys->werrstr(Ebadarg);
			return nil;
		}
		p := g64(fh, 0).t0;
		path: string;
		case name {
		".." =>	path = sprint("%s/%bux", pathstyxupmtpt, p);
		* =>	path = sprint("%s/%bux/%s", pathstyxmtpt, p, "/"+name);
		}
		(ok, dir) := sys->stat(path);
		if(ok != 0)
			return nil;
		return fhbuf(dir.qid.path);
	}

	path := fhpath(fh);
	if(path == nil)
		return nil;
	if(name == "..") {
		path = str->splitstrr(path, "/").t0;
		if(path != "/")
			path = "/";
	} else {
		if(path != "/")
			path += "/";
		path += name;
	}
	(ok, nil) := sys->stat(path);
	if(ok != 0)
		return nil;
	return fhputpath(path);
}

fhlookupdir(fh: array of byte, dir: Sys->Dir): array of byte
{
	if(fhqidpath)
		return fhbuf(dir.qid.path);
	return fhlookup(fh, dir.name);
}

fhstat(fh: array of byte): (int, Sys->Dir)
{
	p := fhpath(fh);
	if(p == nil)
		return (-1, sys->zerodir);
	return sys->stat(p);
}

fhwstat(fh: array of byte, dir: Sys->Dir): int
{
	p := fhpath(fh);
	if(p == nil)
		return -1;
	return sys->wstat(p, dir);
}

fhopen(srv: ref Srv, fh: array of byte, mode: int, usecache: int): ref Sys->FD
{
	p := fhpath(fh);
	if(p == nil)
		return nil;
	if(usecache) {
		srv.fdopenc <-= (fh, p, mode, rc := chan of (ref Sys->FD, string));
		(fd, err) := <-rc;
		if(err != nil)
			sys->werrstr(err);
		return fd;
	}
	return sys->open(p, mode);
}

fhcreate(fh: array of byte, name: string, mode, perm: int): array of byte
{
	p := fhpath(fh);
	if(p == nil)
		return nil;
	if(p != "/")
		p += "/";
	p += name;
	fd := sys->create(p, mode, perm);
	if(fd == nil)
		return nil;
	if(fhqidpath) {
		(ok, dir) := sys->fstat(fd);
		if(ok != 0)
			return nil;
		return fhbuf(dir.qid.path);
	}
	return fhputpath(p);
}

fhattr(fh: array of byte): ref Attr
{
	(ok, dir) := fhstat(fh);
	if(ok == 0)
		attr := ref dir2attr(dir);
	return attr;
}

dir2verifier(dir: Sys->Dir): big
{
	return (big dir.qid.vers<<32)|big dir.mtime;
}

fhverifier(fh: array of byte): big
{
	(ok, dir) := fhstat(fh);
	if(ok != 0)
		return big 0;
	return dir2verifier(dir);
}

verifier(fd: ref Sys->FD): big
{
	(ok, dir) := sys->fstat(fd);
	if(ok != 0)
		return big 0;
	return dir2verifier(dir);
}

fstypes := array[] of {
nfs->FTreg => "reg",
nfs->FTdir => "dir",
nfs->FTblk => "blk",
nfs->FTchr => "chr",
nfs->FTlnk => "lnk",
nfs->FTsock => "sock",
nfs->FTfifo => "fifo",
};
dir2attr(dir: Sys->Dir): Attr
{
	a: Attr;
	a.ftype = nfs->FTreg;
	if(dir.mode&Sys->DMDIR)
		a.ftype = nfs->FTdir;
	a.mode = dir.mode&8r777;
	a.nlink = 2;	# force copy of write for users try to do that
	a.uid = name2uid(dir.uid);
	a.gid = name2gid(dir.gid);
	a.size = a.used = dir.length;
	a.rdev.major = 0;
	a.rdev.minor = 0;
	a.fsid = (big dir.dtype<<32)|(big dir.dev);
	a.fileid = dir.qid.path;
	a.atime = dir.atime;
	a.mtime = a.ctime = dir.mtime;
if(dflag) say(sprint("dir2attr, type %s, mode %o size %bud", fstypes[a.ftype], a.mode, a.size));
	return a;
}

badname(s: string): int
{
	return s == "" || s == "." || s == "..";
}

sattr2dir(s: Sattr, mode: int): (Sys->Dir, int)
{
	bad := 0;
	ndir := sys->nulldir;
	if(s.setmode) {
		ndir.mode = (mode&~8r777) | (s.mode&8r777);
		bad = bad || s.mode&~(Sys->DMDIR|8r777);
	}
	if(s.setuid)
		ndir.uid = uid2name(s.uid);
	if(s.setgid)
		ndir.gid = gid2name(s.gid);
	if(s.setsize)
		ndir.length = s.size;
	case s.setatime {
	nfs->SETdontchange =>	;
	nfs->SETtoservertime =>	ndir.atime = now();
	nfs->SETtoclienttime =>	ndir.atime = s.atime;
	* =>	bad = 1;
	}
	case s.setmtime {
	nfs->SETdontchange =>	;
	nfs->SETtoservertime =>	ndir.mtime = now();
	nfs->SETtoclienttime =>	ndir.mtime = s.mtime;
	* =>	bad = 1;
	}
	return (ndir, bad);
}

entrysize(e: Entry): int
{
	# bool more, id, name, cookie
	return 4+8+pstr(nil, 0, e.name)+8;
}

entryplussize(e: Entryplus, with: int): int
{
	# bool more, id, name, cookie;  attr, fh
	n := 4+8+pstr(nil, 0, e.name)+8;
	if(with)
		n += pboolattr(nil, 0, e.attr)+pboolopaque(nil, 0, e.fh);
	return n;
}

errno(): int
{
	s := sprint("%r");
	v := errno0(s);
if(dflag) say(sprint("errno, s %q, v %d", s, v));
	return v;
}

Ebadarg: con "bad arg in system call";
Eperm: con "permission denied";

errnomap := array[] of {
(nfs->Eperm,	"permission denied"),
(nfs->Enoent,	"does not exist"),
(nfs->Enoent,	"no such"),
(nfs->Eexist,	"already exists"),
(nfs->Enotdir,	"not a directory"),
(nfs->Eperm,	"forbids creation"),
(nfs->Einval,	"bad character"),
(nfs->Einval,	"file name syntax"),
(nfs->Enxio,	"inappropriate"),
(nfs->Einval,	"bad arg in system call"),
(nfs->Eio,	"i/o"),
};
errno0(s: string): int
{
	for(i := 0; i < len errnomap; i++)
		if(index(errnomap[i].t1, s) >= 0)
			return errnomap[i].t0;
	return nfs->Eserverfault;
}

# called from progs that bind styxfd on /, meaning they have no /dev/time
now(): int
{
	n := sys->pread(timefd, buf := array[16] of byte, len buf, big 0);
	if(n <= 0)
		return 0;
	return int (big string buf[:n]/big 1000000);
}

# same as now()
kill(pid: int)
{
	writefile(sprint("#p/%d/ctl", pid), 0, array of byte "kill");
}

killgrp(pid: int)
{
	writefile(sprint("#p/%d/ctl", pid), 0, array of byte "killgrp");
}

say(s: string)
{
	if(dflag)
		warn(s);
}

failall(s: string)
{
	warn(s);
	killgrp(pid());
	raise "fail:"+s;
}
