implement Nfssrv;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "daytime.m";
	daytime: Daytime;
include "string.m";
	str: String;
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, g64, gopaque, p32, p64, popaque: import sunrpc;
	Parse, Badrpc: import sunrpc;
	Badrpcversion, Badprog, Badproc, Badprocargs: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "../lib/mntrpc.m";
	mnt: Mntrpc;
	Tmnt, Rmnt, Export: import mnt;
include "../lib/nfsrpc.m";
	nfs: Nfsrpc;
	Tnfs, Rnfs: import nfs;
	Attr, Sattr, Time, Specdata, Weakattr, Weakdata, Dirargs, Nod, Entry, Entryplus: import nfs;
	Rgetattr, Rlookup, Raccess, Rreadlink, Rread, Rwrite, Rchange, Rreaddir, Rreaddirplus, Rfsstat, Rfsinfo, Rpathconf, Rcommit: import nfs;

Nfssrv: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
nfsport := 2049;
mntport := 39422;

regfd: ref Sys->FD;  # global, so we keep a reference until nfssrv dies
verfcookie := array[8] of {* => byte 0};

nilwd: Weakdata;

uname: string;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	daytime = load Daytime Daytime->PATH;
	str = load String String->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	mnt = load Mntrpc Mntrpc->PATH;
	mnt ->init();
	nfs = load Nfsrpc Nfsrpc->PATH;
	nfs->init();

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

	uname = "none";
	fd := sys->open("/dev/user", Sys->OREAD);
	if(fd != nil) {
		n := sys->readn(fd, buf := array[128] of byte, len buf);
		if(n > 0)
			uname = string buf[:n];
	}

	sys->pctl(Sys->NEWPGRP, nil);

	regfd = sys->open("/chan/portmapper", Sys->OWRITE);
	if(regfd == nil)
		failall(sprint("open /chan/portmapper: %r"));
	if(sys->fprint(regfd, "add %d %d tcp %d\n", mnt->ProgMnt, mnt->VersMnt, mntport) < 0)
		failall(sprint("registering mnt tcp: %r"));
	if(sys->fprint(regfd, "add %d %d udp %d\n", mnt->ProgMnt, mnt->VersMnt, mntport) < 0)
		failall(sprint("registering mnt udp: %r"));
	if(sys->fprint(regfd, "add %d %d tcp %d\n", nfs->ProgNfs, nfs->VersNfs, nfsport) < 0)
		failall(sprint("registering nfs tcp: %r"));
	if(sys->fprint(regfd, "add %d %d udp %d\n", nfs->ProgNfs, nfs->VersNfs, nfsport) < 0)
		failall(sprint("registering nfs udp: %r"));

	p64(verfcookie, 0, (big sys->millisec()<<32)|big daytime->now());
	initfh();

	spawn listen(nfsport, nfssrv);
	spawn listenudp(nfsport, nfstransact);
	spawn listen(mntport, mntsrv);
	spawn listenudp(mntport, mnttransact);
}

filehandlelock: chan of int;
initfh()
{
	filehandlelock = chan[1] of int;
	filehandlelock <-= 1;
	fhput("/");
}

fhlock()
{
	<-filehandlelock;
}

fhunlock()
{
	filehandlelock <-= 1;
}


Fh: adt {
	fh:	big;
	path:	string;
	gen:	int;
};

Dh: adt {
	cookie:	big;
	fd:	ref Sys->FD;
	dirs:	array of Sys->Dir;
	off:	int;
};

filehandles := array[2**14] of {* => Fh (big 0, nil, 0)};  # 2**7 lists of 2**7 elements
dirhandles: list of ref Dh;
dircookiegen := big 0;

Basemask: con (1<<7)-1;
Basesize: con (1<<7);
fhgen := big 1;
fhusegen := 0;

fhget(fhbuf: array of byte): string
{
	if(len fhbuf != 8)
		return nil;
	fh := g64(fhbuf, 0).t0;
	base := int fh&Basemask;

	fhlock();
	end := (base+1)*Basesize;
	path: string;
	for(i := base*Basesize; i < end; i++) {
		if(filehandles[i].fh == fh) {
			if(++fhusegen < 0)
				fhusegen = 1;
			filehandles[i].gen = fhusegen;
			path = filehandles[i].path;
			break;
		}
	}
	fhunlock();
say(sprint("fhget, fh %s -> path %q", hex(fhbuf), path));
	return path;
}

fhdel(fhbuf: array of byte)
{
	if(len fhbuf != 8)
		return;
	fh := g64(fhbuf, 0).t0;
	base := int fh&Basemask;

	fhlock();
	end := (base+1)*Basesize;
	for(i := base*Basesize; i < end; i++) {
		if(filehandles[i].fh == fh) {
			filehandles[i].path = nil;
			filehandles[i].gen = 0;
			break;
		}
	}
	fhunlock();
}

fhput(path: string): array of byte
{
	base := pathhash(path);

	fhlock();
	end := (base+1)*Basesize;
	oldest := base*Basesize;
	oldestgen := filehandles[oldest].gen;
	fh: array of byte;
	for(i := base*Basesize; i < end; i++) {
		if(filehandles[i].path == path) {
			if(++fhusegen < 0)
				fhusegen = 1;
			filehandles[i].gen = fhusegen;
			fh = array[8] of byte;
			p64(fh, 0, filehandles[i].fh);
			break;
		} else if(filehandles[i].path != "/") {
			gen := filehandles[i].gen;
			if(oldestgen > fhusegen && gen < oldestgen && gen > fhusegen
			|| oldestgen < fhusegen && (gen < oldestgen || gen > fhusegen)) {
				oldestgen = gen;
				oldest = i;
			}
		}
	}
	if(fh == nil) {
		filehandles[oldest].fh = ((++fhgen)<<7)|big base;
		filehandles[oldest].path = path;
		if(++fhusegen < 0)
			fhusegen = 1;
		filehandles[i].gen = fhusegen;

		fh = array[8] of byte;
		p64(fh, 0, filehandles[oldest].fh);
		
	}
	fhunlock();
say(sprint("fhput, path %q, base %x -> fh %s", path, base, hex(fh)));
	return fh;
}

pathhash(p: string): int
{
	v := 0;
	for(i := 0; i < len p; i++)
		v += int p[i];
	return v&Basemask;
}


dirdel(cookie: big)
{
say(sprint("dirdel, cookie %bd", cookie));
	nl: list of ref Dh;
	for(l := dirhandles; l != nil; l = tl l)
		if((hd l).cookie != cookie)
			nl = hd l::nl;
	dirhandles = nl;
}

dirput(fd: ref Sys->FD): ref Dh
{
	dh := ref Dh (dircookiegen++, fd, nil, 0);
	dirhandles = dh::dirhandles;
say(sprint("dirput, new cookie %bd", dh.cookie));
	return dh;
}

dirget(a: ref Attr, cookie: big): ref Dh
{
say(sprint("dirget, cookie %bd", cookie));
	if(a == nil) {
		dirdel(cookie);
		return nil;
	}
	for(l := dirhandles; l != nil; l = tl l)
		if((hd l).cookie == cookie) {
say(sprint("dirget, cookie %bd, hit", cookie));
			return hd l;
		}
say(sprint("dirget, cookie %bd, miss", cookie));
	return nil;
}

dirnext(dh: ref Dh): (int, ref Sys->Dir)
{
	if(dh.off >= len dh.dirs) {
		dh.off = 0;
		n: int;
		(n, dh.dirs) = sys->dirread(dh.fd);
say(sprint("dirnext, dirread gave %d dirs (%d)", len dh.dirs, n));
		if(n <= 0)
			return (0, nil);
	}
	dh.cookie = dircookiegen++;
	d := ref dh.dirs[dh.off++];
say(sprint("dirnext, have dir elem %q, new cookie %bd", d.name, dh.cookie));
	return (0, d);
}

parent(p: string): string
{
say(sprint("parent() for p %q", p));
	if(p == "/")
		return p;
	p = str->splitstrr(p, "/").t0;
	if(p == nil)
		p = "/";
	return p;
}

makepath(dir, file: string): string
{
	p := "/"+file;
	if(dir != "/")
		p = dir+p;
	return p;
}

badname(s: string): int
{
	return s == "" || s == "." || s == "..";
}

sattr2dir(s: Sattr): (Sys->Dir, int)
{
	bad := 0;
	ndir := sys->nulldir;
	if(s.setmode) {
		ndir.mode = s.mode&8r777;
		bad = bad || s.mode&~8r777;
	}
	# xxx uid & gid
	bad = bad || s.setuid || s.setgid;
	if(s.setsize)
		ndir.length = s.size;
	case s.setatime {
	nfs->SETdontchange =>	;
	nfs->SETtoservertime =>	ndir.atime = daytime->now();
	nfs->SETtoclienttime =>	ndir.atime = s.atime;
	* =>	bad = 1;
	}
	case s.setmtime {
	nfs->SETdontchange =>	;
	nfs->SETtoservertime =>	ndir.mtime = daytime->now();
	nfs->SETtoclienttime =>	ndir.mtime = s.mtime;
	* =>	bad = 1;
	}
	return (ndir, bad);
}

getdir(cookie: big, attr: ref Attr, path: string): (ref Dh, int)
{
	if(cookie == big 0) {
say("t.cookie == 0, opening dir");
		dfd := sys->open(path, Sys->OREAD);
		if(dfd == nil) {
say(sprint("readdir, open path %q failed: %r", path));
			return (nil, nfs->Eserverfault);
		}
		return (dirput(dfd), nfs->Eok);
	}

say("dir already open, using cookie");
	dh := dirget(attr, cookie);
	if(dh == nil) {
say(sprint("readdir, old cookie"));
		return (nil, nfs->Ebadcookie);
	}
	return (dh, nfs->Eok);
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
			warn(err);
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
	pick t := tt {
	Null =>
		say("mnt, null");
		r = ref Rmnt.Null (rok);
	Mnt =>
		say("mnt, mnt");
		fh := fhput("/");
		auths := array[] of {sunrpc->Asys};
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
		exports := array[] of {Export ("/", array[] of {"all"})};
		r = ref Rmnt.Export (rok, exports);
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
Top:
	pick t := tt {
	Null =>
		rr = ref Rnfs.Null;

	Getattr =>
		rr = r := ref Rnfs.Getattr;
		path := fhget(t.fh);
		if(path == nil) {
			r.r = ref Rgetattr.Fail (nfs->Estale);
			break;
		}
		(a, errno) := getattr(path);
		if(a == nil)
			r.r = ref Rgetattr.Fail (errno);
		else
			r.r = ref Rgetattr.Ok (*a);

	Setattr =>
		rr = r := ref Rnfs.Setattr;
		r.weak = nilwd;
		path := fhget(t.fh);
		if(path == nil) {
			r.status = nfs->Estale;
			break;
		}

		if(t.haveguard) {
			(ok, dir) := sys->stat(path);
			if(ok < 0) {
				r.status = nfs->Eserverfault;
				break;
			}
			if(dir.mtime != t.guardctime) {
				r.status = nfs->Enotsync;
				break;
			}
		}

		# build the new Dir, starting with all don't cares.
		# "bad" indicates whether we encountered a request we don't supported.
		(ndir, bad) := sattr2dir(t.newattr);
		if(sys->wstat(path, ndir) < 0) {
			warn(sprint("wstat %q: %r", path));
			r.status = nfs->Eserverfault;
			break;
		}

		if(bad)
			r.status = nfs->Einval;
		else
			r.status = nfs->Eok;

	Lookup =>
		rr = r := ref Rnfs.Lookup;
		dirpath := fhget(t.where.fh);
		if(dirpath == nil) {
say(sprint("lookup, stale fh %s", hex(t.where.fh)));
			r.r = ref Rlookup.Fail (nfs->Estale, nil);
			break;
		}
		dirattr := getattr(dirpath).t0;
		npath: string;
say(sprint("lookup, dirpath %q, name %q", dirpath, t.where.name));
		case t.where.name {
		"" =>
			r.r = ref Rlookup.Fail (nfs->Enoent, dirattr);
			break Top;
		"." =>
			npath = dirpath;
		".." =>
			npath = parent(dirpath);
		* =>
			npath = makepath(dirpath, t.where.name);
		}
say(sprint("lookup, dirpath %q, name %q, npath %q", dirpath, t.where.name, npath));
		(fattr, status) := getattr(npath);
		if(fattr == nil) {
			status = nfs->Enoent;
			r.r = ref Rlookup.Fail (status, dirattr);
			break;
		}
		fh := fhput(npath);
		r.r = ref Rlookup.Ok (fh, fattr, dirattr);

	Access =>
		rr = r := ref Rnfs.Access;
		path := fhget(t.fh);
		if(path == nil) {
			r.r = ref Raccess.Fail (nfs->Estale, nil);
			break;
		}

		# we can only approximate...
		# if we are owner, use owner perms.
		# otherwise see if we are group.
		# otherwise uses other's perms.
		# we can't determine if we are part of other groups.
		access := 0;
		(ok, dir) := sys->stat(path);
		if(ok == 0) {
			perm: int;
			if(dir.uid == uname)
				perm = dir.mode>>6;
			else if(dir.gid == uname)
				perm = dir.mode>>3;
			else
				perm = dir.mode;
			say(sprint("mode 8r%uo, uid %q gid %q uname %q, perm 8r%uo", dir.mode, dir.uid, dir.gid, uname, perm));
			perm &= (1<<3)-1;
			br := bw := bx := 0;
			if(perm&8r4) br = ~0;
			if(perm&8r2) bw = ~0;
			if(perm&8r1) bx = ~0;
			say(sprint("perm 8r%uo, br %ux bw %ux Bx %ux", perm, br, bw, bx));
			access |= nfs->ACread&br;
			access |= (nfs->ACmodify|nfs->ACextend|nfs->ACdelete)&bw;
			access |= (nfs->AClookup|nfs->ACexecute)&bx;
		} else
			say(sprint("stat %q failed: %r", path));
say(sprint("access, path %q, access 0x%x (requested 0x%x", path, access, t.access));
		r.r = ref Raccess.Ok (getattr(path).t0, access);

	Readlink =>
		rr = r := ref Rnfs.Readlink;
		r.r = ref Rreadlink.Fail (nfs->Enotsupp, nil);

	Read =>
		rr = r := ref Rnfs.Read;
		path := fhget(t.fh);
		if(path == nil) {
			r.r = ref Rread.Fail (nfs->Estale, nil);
			break;
		}
		# xxx should probably cache opens... per user?
		ffd := sys->open(path, Sys->OREAD);
		if(ffd == nil) {
			r.r = ref Rread.Fail (nfs->Eserverfault, getattr(path).t0);
			break;
		}
		count := t.count;
		if(count > Sys->ATOMICIO)
			count = Sys->ATOMICIO;
		rbuf := array[count] of byte;
		n := sys->pread(ffd, rbuf, len rbuf, t.offset);
		if(n < 0) {
			r.r = ref Rread.Fail (nfs->Eserverfault, getattr(path).t0);
			break;
		}
		r.r = ref Rread.Ok (getattr(path).t0, n, n==0, rbuf[:n]);

	Write =>
		rr = r := ref Rnfs.Write;
		path := fhget(t.fh);
		if(path == nil) {
			r.r = ref Rwrite.Fail (nfs->Estale, nilwd);
			break;
		}
		# xxx should probably cache opens... per user?
		ffd := sys->open(path, Sys->OWRITE);
		if(ffd == nil) {
			r.r = ref Rwrite.Fail (nfs->Eserverfault, nilwd);
			break;
		}
		n := sys->pwrite(ffd, t.data, len t.data, t.offset);
		if(n != len t.data) {
			r.r = ref Rwrite.Fail (nfs->Eserverfault, nilwd);
			break;
		}
		how := t.stablehow;
		case t.stablehow {
		nfs->WriteUnstable =>
			;
		nfs->WriteDatasync or
		nfs->WriteFilesync =>
			if(sys->wstat(path, sys->nulldir) < 0) {
				r.r = ref Rwrite.Fail (nfs->Eserverfault, nilwd);
				break Top;
			}
			how = nfs->WriteFilesync;
		* =>
			raise "internal error";
		}
		r.r = ref Rwrite.Ok (nilwd, n, how, verfcookie);

	Create =>
		rr = r := ref Rnfs.Create;
		r.r = e := ref Rchange.Fail;
		e.weak = nilwd;

		dirpath := fhget(t.where.fh);
		if(dirpath == nil) {
			e.status = nfs->Estale;
			break;
		}
		if(badname(t.where.name)) {
			e.status = nfs->Einval;
			break;
		}

		npath := makepath(dirpath, t.where.name);
		mode := Sys->ORDWR;
		perm := 8r777;
		sattr: ref Sattr;
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
		nfd := sys->create(npath, mode, perm);
		if(nfd == nil) {
			e.status = nfs->Einval;
			break;
		}
		if(sattr != nil) {
			(dir, bad) := sattr2dir(*sattr);
			if(sys->wstat(npath, dir) < 0) {
				e.status = nfs->Einval;
				break;
			}
			if(bad) {
				e.status = nfs->Einval;
				break;
			}
		}

		nfh := fhput(npath);
		r.r = ref Rchange.Ok (nfh, getattr(npath).t0, nilwd);

	Mkdir =>
		rr = r := ref Rnfs.Mkdir;
		r.r = e := ref Rchange.Fail;
		e.weak = nilwd;

		dirpath := fhget(t.where.fh);
		if(dirpath == nil) {
			e.status = nfs->Estale;
			break;
		}
		if(badname(t.where.name)) {
			e.status = nfs->Einval;
			break;
		}
		npath := makepath(dirpath, t.where.name);
		perm := 8r777;
		if(t.attr.setmode)
			perm = t.attr.mode&8r777;
		nfd := sys->create(npath, Sys->OREAD|Sys->OEXCL, Sys->DMDIR|perm);
		if(nfd == nil) {
say(sprint("create dir %q: %r", npath));
			e.status = nfs->Eserverfault;
			break;
		}

		(ndir, bad) := sattr2dir(t.attr);
		if(sys->wstat(npath, ndir) < 0) {
			warn(sprint("wstat %q, for mkdir: %r", npath));
			e.status = nfs->Einval;
			break;
		}
		if(bad) {
			e.status = nfs->Einval;
			break;
		}

		nfh := fhput(npath);
		r.r = ref Rchange.Ok (nfh, getattr(npath).t0, nilwd);

	Symlink =>
		rr = r := ref Rnfs.Symlink;
		r.r = ref Rchange.Fail (nfs->Enotsupp, nilwd);

	Mknod =>
		rr = r := ref Rnfs.Mknod;
		r.r = ref Rchange.Fail (nfs->Enotsupp, nilwd);

	Remove =>
		rr = r := ref Rnfs.Remove;
		r.weak = nilwd;
		dirpath := fhget(t.where.fh);
		if(dirpath == nil) {
			r.status = nfs->Estale;
			break;
		}
		if(badname(t.where.name)) {
			r.status = nfs->Einval;
			break Top;
		}
		path := makepath(dirpath, t.where.name);
		if(sys->remove(path) < 0) {
say(sprint("remove %q failed: %r", path));
			r.status = nfs->Eserverfault;
			break;
		}
		r.status = nfs->Eok;

	Rmdir =>
		rr = r := ref Rnfs.Rmdir;
		r.weak = nilwd;
		dirpath := fhget(t.where.fh);
		if(dirpath == nil) {
			r.status = nfs->Estale;
			break;
		}
		if(badname(t.where.name)) {
			r.status = nfs->Einval;
			break Top;
		}
		path := makepath(dirpath, t.where.name);
		if(sys->remove(path) < 0) {
say(sprint("rmdir %q failed: %r", path));
			r.status = nfs->Eserverfault;
			break;
		}
		r.status = nfs->Eok;

	Rename =>
		rr = r := ref Rnfs.Rename;
		r.fromdir = nilwd;
		r.todir = nilwd;

		odirpath := fhget(t.owhere.fh);
		ndirpath := fhget(t.nwhere.fh);
		if(odirpath == nil || ndirpath == nil) {
			r.status = nfs->Estale;
			break;
		}
		if(odirpath != ndirpath) {
			# we don't support renames to different directories
			r.status = nfs->Einval;
			break;
		}
		if(badname(t.owhere.name)) {
			r.status = nfs->Einval;
			break Top;
		}
		if(badname(t.nwhere.name)) {
			r.status = nfs->Einval;
			break Top;
		}
		opath := makepath(odirpath, t.owhere.name);

		ndir := sys->nulldir;
		ndir.name = t.nwhere.name;
		if(sys->wstat(opath, ndir) < 0) {
			r.status = nfs->Einval;
			break;
		}

		r.status = nfs->Eok;

	Link =>
		rr = ref Rnfs.Link (nil, nfs->Enotsupp, nil, nilwd);

	Readdir =>
		rr = r := ref Rnfs.Readdir;
		path := fhget(t.fh);
		if(path == nil) {
say("readdir, stale");
			r.r = ref Rreaddir.Fail (nfs->Estale, nil);
			break;
		}
		attr := getattr(path).t0;
		(dh, status) := getdir(t.cookie, attr, path);
		if(dh == nil) {
			r.r = ref Rreaddir.Fail (status, nil);
			break;
		}

		eof := 0;
		entries: list of Entry;
		for(n := 0; n < 16; n++) {  # xxx go on until no more
			(ok, dir) := dirnext(dh);
			if(ok < 0) {
say("dirnext failed");
				dirdel(dh.cookie);
				r.r = ref Rreaddir.Fail (nfs->Eserverfault, nil);
				break Top;
			}
			if(dir == nil) {
say("end of dir reached");
				eof = 1;
				dirdel(dh.cookie);
				break;
			}
			# if(!nfs->readdirfits(...))
			# dirunnext(dh, entry);
			e := Entry (dir.qid.path, dir.name, dh.cookie);
			entries = e::entries;
		}
say(sprint("readdir, len entries %d, eof %d", len entries, eof));
		ents := array[len entries] of Entry;
		i := len entries-1;
		for(; entries != nil; entries = tl entries)
			ents[i--] = hd entries;
		r.r = ref Rreaddir.Ok (attr, verfcookie, ents, eof);

	Readdirplus =>
		rr = r := ref Rnfs.Readdirplus;
		path := fhget(t.fh);
		if(path == nil) {
say("readdirplus, stale");
			r.r = ref Rreaddirplus.Fail (nfs->Estale, nil);
			break;
		}
		attr := getattr(path).t0;
		(dh, status) := getdir(t.cookie, attr, path);
		if(dh == nil) {
			r.r = ref Rreaddirplus.Fail (status, nil);
			break;
		}

		eof := 0;
		entries: list of Entryplus;
		for(n := 0; n < 16; n++) {  # xxx go on until no more
			(ok, dir) := dirnext(dh);
			if(ok < 0) {
say("dirnext failed");
				dirdel(dh.cookie);
				r.r = ref Rreaddirplus.Fail (nfs->Eserverfault, nil);
				break Top;
			}
			if(dir == nil) {
say("end of dir reached");
				eof = 1;
				dirdel(dh.cookie);
				break;
			}
			# if(!nfs->readdirfits(...))
			# dirunnext(dh, entry);

			# xxx have to verify this after i have more stuff working...
			# sending a file handle for each entryplus seems superfluous.
			# but linux' in-kernel nfs client seems to treat absent file handles as zero-length file handles,
			# so include a file handle to help linux clients.
			npath := makepath(path, dir.name);
			e := Entryplus (dir.qid.path, dir.name, dh.cookie, getattr(npath).t0, fhput(npath));
			entries = e::entries;
		}
say(sprint("readdirplus, len entries %d, eof %d", len entries, eof));
		ents := array[len entries] of Entryplus;
		i := len entries-1;
		for(; entries != nil; entries = tl entries)
			ents[i--] = hd entries;
		r.r = ref Rreaddirplus.Ok (attr, verfcookie, ents, eof);

	Fsstat =>
		rr = r := ref Rnfs.Fsstat;
		path := fhget(t.rootfh);
		if(path == nil) {
			r.r = ref Rfsstat.Fail (nfs->Estale, nil);
			break;
		}
		r.r = e := ref Rfsstat.Ok;
		(e.attr, nil) = getattr(path);
		e.tbytes = big 0;  # total
		e.fbytes = big 0;  # free
		e.abytes = big 0;  # available to user
		e.tfiles = big 0;  # same, but "inodes"
		e.ffiles = big 0;
		e.afiles = big 0;
		e.invarsec = 0;

	Fsinfo =>
		rr = r := ref Rnfs.Fsinfo;
		path := fhget(t.rootfh);
		if(path == nil) {
			r.r = ref Rfsinfo.Fail (nfs->Estale, nil);
			break;
		}
		r.r = e := ref Rfsinfo.Ok;
		(e.attr, nil) = getattr(path);
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
		path := fhget(t.fh);	
		if(path == nil) {
			r.r = ref Rpathconf.Fail (nfs->Estale, nil);
			break;
		}
		e := r.r = ref Rpathconf.Ok;
		e.attr = getattr(path).t0;
		e.linkmax = 1;
		e.namemax = 1024;
		e.notrunc = 1;
		e.chownrestr = 1;
		e.caseinsens = 0;
		e.casepres = 1;

	Commit =>
		rr = r := ref Rnfs.Commit;
		path := fhget(t.fh);
		if(path == nil) {
			r.r = ref Rcommit.Fail (nfs->Estale, nilwd);
			break;
		}
		if(sys->wstat(path, sys->nulldir) != 0) {
			r.r = ref Rcommit.Fail (nfs->Eserverfault, nilwd);
			break;
		}
		r.r = ref Rcommit.Ok (nilwd, verfcookie);

	* =>
		raise "internal error";
	}
	rr.m = rok;
	say("have nfs response");
	return sunrpc->writeresp(fd, pre, pre==nil, rr);
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
getattr(p: string): (ref Attr, int)
{
	(ok, dir) := sys->stat(p);
	if(ok < 0)
		return (nil, nfs->Eperm);
	a := ref Attr;
	a.ftype = nfs->FTreg;
	if(dir.mode&Sys->DMDIR)
		a.ftype = nfs->FTdir;
	a.mode = dir.mode&8r777;
	a.nlink = 1;
	a.uid = a.gid = 0;  # xxx map uname,gname -> uid,gid
	a.size = a.used = dir.length;
	a.rdev.major = 0;
	a.rdev.minor = 0;
	a.fsid = (big dir.dtype<<32)|(big dir.dev);
	a.fileid = dir.qid.path;
	a.atime = dir.atime;
	a.mtime = a.ctime = dir.mtime;
say(sprint("getattr path %q, type %s, mode %o size %bd", p, fstypes[a.ftype], a.mode, a.size));
	return (a, 0);
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
