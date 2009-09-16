implement Nfsfs;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "bufio.m";
	bufio: Bufio;
	Iobuf: import bufio;
include "daytime.m";
	daytime: Daytime;
include "rand.m";
	rand: Rand;
include "string.m";
	str: String;
include "tables.m";
	tables: Tables;
	Table: import tables;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import styx;
include "sunrpc.m";
	sunrpc: Sunrpc;
	Trpc, Rrpc: import sunrpc;
	Parse, Badrpc, Badprog, Badproc, Badprocargs: import sunrpc;
	Authsys, Auth: import sunrpc;
include "../lib/mntrpc.m";
	mntrpc: Mntrpc;
	Tmnt, Rmnt: import mntrpc;
include "../lib/nfsrpc.m";
	nfsrpc: Nfsrpc;
	Tnfs, Rnfs: import nfsrpc;
	Entryplus, Entry, Specdata, Time, Attr, Weakattr, Weakdata, Sattr, Dirargs, Nod, Createhow: import nfsrpc;
	Rfsstat, Rfsinfo: import nfsrpc;
	Estale: import Nfsrpc;
include "portmap.m";
	portmap: Portmap;
include "util0.m";
	util: Util0;
	l2a, kill, killgrp, pid, max, warn, hex: import util;


Nfsfs: module {
	init:	fn(nil: ref Draw->Context, nil: list of string);
};


dflag: int;
uid,
gid:	int;
gids:	list of int;
userfile,
groupfile:	string;
users,
groups:	ref Table[string];

xidgen: int;
nfsfd: ref Sys->FD;
auth: Auth;
nullverf: Auth;
sysname := "localhost";

rootfh: array of byte;

msize: int;
fidtab: ref Table[ref Fid];	# fid -> Fid

Fh: adt {
	fh:	array of byte;
	parent,		# starts out empty, then "elem/" appended
	elem:	string;
};

pathgen: big;
Fid: adt {
	fid:	int;
	fh:	ref Fh;
	isdir:	int;
	path:	big;
	isopen:	int;
	access:	int;
	entries:	array of Nfsrpc->Entryplus;
	dircookie:	big;
	dircookieverf:	array of byte;
	direof:	int;

	qid:	fn(f: self ref Fid): Sys->Qid;
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	bufio = load Bufio Bufio->PATH;
	daytime = load Daytime Daytime->PATH;
	str = load String String->PATH;
	rand = load Rand Rand->PATH;
	tables = load Tables Tables->PATH;
	styx = load Styx Styx->PATH;
	styx->init();
	portmap = load Portmap Portmap->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	mntrpc = load Mntrpc Mntrpc->PATH;
	mntrpc->init();
	nfsrpc = load Nfsrpc Nfsrpc->PATH;
	nfsrpc->init();
	util = load Util0 Util0->PATH;
	util->init();

	sys->pctl(Sys->NEWPGRP, nil);

	rand->init(sys->millisec()^sys->pctl(0, nil));
	xidgen = rand->rand((1<<31)-1);

	arg->init(args);
	arg->setusage(arg->progname()+" [-d] [-u uid] [-g gid,...] [-p passwd group] host path");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	portmap->dflag = sunrpc->dflag = mntrpc->dflag = nfsrpc->dflag = dflag++;
		'u' =>	uid = int arg->arg();
		'g' =>
			l := sys->tokenize(arg->arg(), ",").t1;
			if(l == nil)
				arg->usage();
			gid = int hd l;
			l = tl l;
			for(; l != nil; l = tl l)
				gids = int hd l::gids;
		'p' =>
			userfile = arg->arg();
			groupfile = arg->arg();
		* =>
			arg->usage();
		}
	args = arg->argv();
	if(len args != 2)
		arg->usage();

	host := hd args;
	path := hd tl args;

	readsysname();
	users = users.new(31, nil);
	if(userfile != nil)
		readusers();
	groups = users.new(31, nil);
	if(groupfile != nil)
		readgroups();

	nfsstat := sys->file2chan("/chan", "nfsstat");
	if(nfsstat == nil) {
		warn(sprint("file2chan nfsstat: %r"));
		nfsstat = bogusfileio();
	}
	nfsinfo := sys->file2chan("/chan", "nfsinfo");
	if(nfsinfo == nil) {
		warn(sprint("file2chan nfsinfo: %r"));
		nfsinfo = bogusfileio();
	}

	mntport := portmap->getport(1, host, nil, Mntrpc->ProgMnt, Mntrpc->VersMnt, Portmap->Tcp);
	if(mntport <= 0)
		fail(sprint("mount port: %r"));
	nfsport := portmap->getport(1, host, nil, Nfsrpc->ProgNfs, Nfsrpc->VersNfs, Portmap->Tcp);
	if(nfsport <= 0)
		fail(sprint("nfs port: %r"));

	asys := ref Authsys (0, sysname, uid, gid, l2aint(gids));
	asysbuf := array[asys.size()] of byte;
	asys.pack(asysbuf, 0);
	auth = Auth (Sunrpc->Asys, asysbuf);
	nullverf = Auth (Sunrpc->Anone, array[0] of byte);

	err: string;
	(rootfh, nil, err) = mnt(1, host, mntport, path, auth);
	if(err != nil)
		fail(err);
	if(dflag) say(sprint("rootfh %s", hex(rootfh)));

	nfsaddr := sprint("tcp!%s!%d", host, nfsport);
	(ok, conn) := sys->dial(nfsaddr, nil);
	if(ok != 0)
		fail(sprint("dial %q: %r", nfsaddr));
	nfsfd = conn.dfd;
	if(dflag) say("dialed nfs");

	styxfd := sys->fildes(0);
	fidtab = fidtab.new(31, nil);

	spawn styxread(styxfd, msgc := chan of ref Tmsg, nextc := chan of int);
	msize = Styx->MAXRPC;
	nextc <-= msize;

nextstyx:
	for(;;) alt {
	(o, n, nil, rc) := <-nfsinfo.read =>
		if(rc == nil)
			continue;
		r: ref Rfsinfo.Ok;
		(r, err) = nfsfsinfo(ref Fh (rootfh, nil, nil));
		buf: array of byte;
		if(err == nil) {
			buf = array of byte packfsinfo(r);
			if(o > len buf)
				o = len buf;
			if(o+n > len buf)
				n = len buf-o;
			buf = buf[o:o+n];
		}
		rc <-= (buf, err);

	(o, n, nil, rc) := <-nfsstat.read =>
		if(rc == nil)
			continue;
		r: ref Rfsstat.Ok;
		(r, err) = nfsfsstat(ref Fh (rootfh, nil, nil));
		buf: array of byte;
		if(err == nil) {
			buf = array of byte packfsstat(r);
			if(o > len buf)
				o = len buf;
			if(o+n > len buf)
				n = len buf-o;
			buf = buf[o:o+n];
		}
		rc <-= (buf, err);

	(nil, nil, nil, rc) := <-nfsinfo.write =>
		if(rc != nil)
			rc <-= (-1, "no wites");
	(nil, nil, nil, rc) := <-nfsstat.write =>
		if(rc != nil)
			rc <-= (-1, "no wites");

	tm := <-msgc =>
		if(tm == nil)
			break nextstyx;
		pick m := tm {
		Readerror =>
			warn("styx read: "+m.error);
			break nextstyx;
		}
		rm := dostyx(tm);
		rbuf := rm.pack();
		if(sys->write(styxfd, rbuf, len rbuf) != len rbuf) {
			warn("styx write: "+err);
			break nextstyx;
		}
		nextc <-= msize;
	}
	killgrp(pid());
}

bogusfileio(): ref Sys->FileIO
{
	f := ref Sys->FileIO;
	f.read = chan of (int, int, int, Sys->Rread);
	f.write = chan of (int, array of byte, int, Sys->Rwrite);
	return f;
}

styxread(fd: ref Sys->FD, msgc: chan of ref Tmsg, nextc: chan of int)
{
	for(;;)
		msgc <-= Tmsg.read(fd, <-nextc);
}

Fid.qid(f: self ref Fid): Sys->Qid
{
	qtype := Sys->QTFILE;
	if(f.isdir)
		qtype = Sys->QTDIR;
	return Sys->Qid (f.path, 0, qtype);
}


styxerror(m: ref Tmsg, s: string): ref Rmsg.Error
{
	return ref Rmsg.Error (m.tag, s);
}

attr2dir(name: string, path: big, a: ref Attr): Sys->Dir
{
	if(name == nil)
		name = "/";
	d: Sys->Dir;
	d.name = name;
	d.uid = lookupid(users, a.uid);
	d.gid = lookupid(groups, a.gid);
	qtype := 0;
	if(a.ftype == Nfsrpc->FTdir)
		qtype = Sys->QTDIR;
	d.qid = Sys->Qid (path, 0, qtype);
	d.mode = a.mode&8r777;
	if(a.ftype == Nfsrpc->FTdir)
		d.mode |= Sys->DMDIR;
	d.atime = a.atime;
	d.mtime = a.mtime;
	d.length = a.size;
	return d;
}

dostyx(tm: ref Tmsg): ref Rmsg
{
	pick m := tm {
	Version =>
		if(m.tag != Styx->NOTAG)
			return styxerror(m, "bad tag for version");
		version: string;
		(msize, version) = styx->compatible(m, Styx->MAXRPC, "9P2000");
		return ref Rmsg.Version (m.tag, msize, version);

	Auth =>
		return styxerror(m, "no auth");

	Attach =>
		f := fidtab.find(m.fid);
		if(f != nil)
			return styxerror(m, "fid in use");
		f = ref Fid (m.fid, ref Fh (rootfh, nil, ""), 1, pathgen++, 0, 0, nil, big 0, nil, 0);
		fidtab.add(f.fid, f);
		return ref Rmsg.Attach (m.tag, f.qid());

	Flush =>
		return ref Rmsg.Flush (m.tag);

	Walk =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(f.isopen)
			return styxerror(m, "fid is open");
		if(!f.isdir && len m.names > 0)
			return styxerror(m, "walk from plain file");
		nf := fidtab.find(m.newfid);
		if(nf != nil)
			return styxerror(m, "fid in use");

		nfh := f.fh.fh;
		isdir := f.isdir;
		name := f.fh.elem;
		qids := array[len m.names] of Sys->Qid;
		nparent := f.fh.parent;
		for(i := 0; i < len m.names; i++) {
			name = m.names[i];
			if(isbadname(name))
				return styxerror(m, sprint("bad argument, name %#q", name));
			nfha: ref Attr;
			err: string;
			(nfh, nfha, err) = nfslookup(ref Fh (nfh, nil, nil), name);
			if(err != nil)
				return styxerror(m, err);
			if(nfha == nil) {
				(nfha, err) = nfsgetattr(ref Fh (nfh, nil, nil));
				if(err != nil)
					return styxerror(m, err);
			}
			isdir = nfha.ftype == Nfsrpc->FTdir;
			qtype := Sys->QTFILE;
			if(isdir)
				qtype = Sys->QTDIR;
			qids[i] = Sys->Qid (pathgen++, 0, qtype);
			if(i+1 < len m.names)
				nparent = pathcombine(nparent, name);
		}
		nf = ref Fid (m.newfid, ref Fh (nfh, nparent, name), isdir, pathgen++, 0, 0, nil, big 0, nil, 0);
		fidtab.add(nf.fid, nf);
		return ref Rmsg.Walk (m.tag, qids);

	Open =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(f.isopen)
			return styxerror(m, "already open");

		if(m.mode & Styx->ORCLOSE)
			return styxerror(m, "ORCLOSE not supported");
		trunc := m.mode & Styx->OTRUNC;
		m.mode &= ~Styx->OTRUNC;
		(access, err) := modeaccess(m.mode);
		if(err != nil)
			return styxerror(m, err);
		naccess: int;
		(naccess, err) = nfsaccess(f.fh, access);
		if(err != nil)
			return styxerror(m, err);
		if((access & naccess) != access)
			return styxerror(m, "permission denied");
		if(trunc && (access & Nfsrpc->ACmodify) == 0)
			return styxerror(m, "bad mode, cannot truncate and read-only");
		if(trunc) {
			sattr := Nfsrpc->nullsattr;
			sattr.setsize = 1;
			sattr.size = big 0;
			err = nfssetattr(f.fh, sattr);
			if(err != nil)
				return styxerror(m, "truncate: "+err);
		}

		f.isopen = 1;
		f.access = access;
		return ref Rmsg.Open (m.tag, f.qid(), max(0, msize-Styx->IOHDRSZ));

	Create =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if(m.name == "." || m.name == "..")
			return styxerror(m, "bad name");
		if(m.mode & Styx->ORCLOSE)
			return styxerror(m, "ORCLOSE not supported");
		if(m.mode & Styx->OTRUNC)
			return styxerror(m, "bogus OTRUNC in create");
		wantdir := m.perm & Sys->DMDIR;
		(access, err) := modeaccess(m.mode);
		if(err != nil)
			return styxerror(m, err);

		pa: ref Attr;
		(pa, err) = nfsgetattr(f.fh);
		if(err != nil)
			return styxerror(m, "stat current directory: "+err);

		basemode := 8r666;
		if(wantdir)
			basemode = 8r777;
		a := Nfsrpc->nullsattr;
		a.setmode = 1;
		a.mode = m.perm & (~basemode | (pa.mode & basemode));
		nfh: array of byte;
		if(wantdir)
			(nfh, err) = nfsmkdir(f.fh, m.name, a);
		else
			(nfh, err) = nfscreate(f.fh, m.name, a);
		if(err == nil && nfh == nil)
			(nfh, nil, err) = nfslookup(f.fh, m.name);
		if(err != nil)
			return styxerror(m, err);
		qtype := 0;
		if(wantdir)
			qtype = Sys->QTDIR;
		fidtab.del(m.fid);
		f = ref Fid (m.fid, ref Fh (nfh, pathcombine(f.fh.parent, f.fh.elem), m.name), wantdir, pathgen++, 0, 0, nil, big 0, nil, 0);
		f.isopen = 1;
		f.access = access;
		fidtab.add(f.fid, f);
		return ref Rmsg.Create (m.tag, f.qid(), max(0, msize-Styx->IOHDRSZ));

	Read =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if((f.access  & Nfsrpc->ACread) == 0)
			return styxerror(m, "not open for reading");

		if(f.isdir) {
			if(m.offset == big 0) {
				f.entries = nil;
				f.dircookie = big 0;
				f.dircookieverf = nil;
				f.direof = 0;
			}
			if(!f.direof && len f.entries == 0) {
				(entries, eof, cookieverf, err) := nfsreaddirplus(f.fh, f.dircookie, f.dircookieverf);
				if(err != nil)
					return styxerror(m, err);
				if(len entries == 0 && !eof)
					return styxerror(m, "nfs readdirplus error, no entries but not eof");

				i := 0;
				nentries := len entries;
				path := pathcombine(f.fh.parent, f.fh.elem);
				while(i < nentries) {
					e := entries[i];
					if(e.name == "." || e.name == "..") {
						entries[i] = entries[--nentries];
						continue;
					}
					if(e.attr == nil) {
						if(e.fh == nil)
							(e.fh, e.attr, err) = nfslookup(f.fh, e.name);
						if(err == nil && e.attr == nil)
							(e.attr, err) = nfsgetattr(ref Fh (e.fh, path, e.name));
						if(err != nil)
							return styxerror(m, err);
					}
					entries[i] = e;
					i++;
				}
				f.entries = entries[:nentries];
				f.dircookieverf = cookieverf;
				f.direof = eof;
				if(len f.entries > 0)
					f.dircookie = f.entries[len f.entries-1].cookie;
			}
			if(len f.entries == 0)
				return ref Rmsg.Read (m.tag, array[0] of byte);

			buf := array[msize-Styx->IOHDRSZ] of byte;
			o := 0;
			for(i := 0; i < len f.entries; i++) {
				e := f.entries[i];
				dir := attr2dir(e.name, pathgen++, e.attr);
				ds := styx->packdirsize(dir);
				if(o+ds > len buf) 
					break;
				buf[o:] = styx->packdir(dir);
				o += ds;
			}
			f.entries = f.entries[i:];
			return ref Rmsg.Read (m.tag, buf[:o]);
		}

		(buf, err) := nfsread(f.fh, m.offset, m.count);
		if(err != nil)
			return styxerror(m, err);
		return ref Rmsg.Read (m.tag, buf);

	Write =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		if((f.access & Nfsrpc->ACmodify) == 0)
			return styxerror(m, "not open for writing");

		(n, err) := nfswrite(f.fh, m.offset, m.data);
		if(err != nil)
			return styxerror(m, err);
		return ref Rmsg.Write (m.tag, n);

	Clunk =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		fidtab.del(m.fid);
		return ref Rmsg.Clunk (m.tag);

	Stat =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");

		(attr, err) := nfsgetattr(f.fh);
		if(err != nil)
			return styxerror(m, err);
		dir := attr2dir(f.fh.elem, f.path, attr);
		return ref Rmsg.Stat (m.tag, dir);

	Remove =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");
		fidtab.del(m.fid);
		if(f.isdir)
			(pfhbuf, nil, err) := nfslookup(f.fh, "..");
		else
			(pfhbuf, nil, err) = pathlookup(f.fh.parent);
		if(err != nil)
			return styxerror(m, "parent directory: "+err);
		pfh := ref Fh (pfhbuf, nil, nil);
		if(f.isdir)
			err = nfsrmdir(pfh, f.fh.elem);
		else
			err = nfsremove(pfh, f.fh.elem);
		if(err != nil)
			return styxerror(m, err);
		return ref Rmsg.Remove (m.tag);

	Wstat =>
		f := fidtab.find(m.fid);
		if(f == nil)
			return styxerror(m, "no such fid");

		d := m.stat;
		if(isnulldir(d)) {
			err := nfscommit(f.fh);
			if(err != nil)
				return styxerror(m, err);
			return ref Rmsg.Wstat (m.tag);
		}

		if(d.name != nil) {
			if(f.isdir)
				(pfhbuf, nil, err) := nfslookup(f.fh, "..");
			else
				(pfhbuf, nil, err) = pathlookup(f.fh.parent);
			if(err != nil)
				return styxerror(m, "parent directory: "+err);
			pfh := ref Fh (pfhbuf, nil, nil);
			err = nfsrename(pfh, f.fh.elem, d.name);
			if(err != nil)
				return styxerror(m, "rename: "+err);
			f.fh.elem = d.name;
			(f.fh.fh, nil, err) = nfslookup(pfh, d.name);
			if(err != nil)
				return styxerror(m, "lookup after rename: "+err);
		}
		if(d.uid != nil || d.gid != nil || d.mode != ~0 || d.atime != ~0 || d.mtime != ~0 || d.length != ~big 0) {
			a := Nfsrpc->nullsattr;
			if(d.uid != nil) {
				a.setuid = 1;
				a.uid = lookupname(users, d.uid);
			}
			if(d.gid != nil) {
				a.setgid = 1;
				a.gid = lookupname(groups, d.gid);
			}
			if(d.mode != ~0) {
				a.setmode = 1;
				a.mode = d.mode & 8r777;
			}
			if(d.atime != ~0) {
				a.setatime = 1;
				a.atime = d.atime;
			}
			if(d.mtime != ~0) {
				a.setmtime = 1;
				a.mtime = d.mtime;
			}
			if(d.length != ~big 0) {
				a.setsize = 1;
				a.size = d.length;
			}
			err := nfssetattr(f.fh, a);
			if(err != nil)
				return styxerror(m, err);
		}
		return ref Rmsg.Wstat (m.tag);
	}
	return styxerror(tm, "internal error");
}

modeaccess(mode: int): (int, string)
{
	a: int;
	case mode {
	Styx->OREAD =>	a = Nfsrpc->ACread;
	Styx->OWRITE =>	a = Nfsrpc->ACmodify;
	Styx->ORDWR =>	a = Nfsrpc->ACread|Nfsrpc->ACmodify;
	Styx->OEXEC =>	a = Nfsrpc->ACread|Nfsrpc->ACexecute;
	* =>
		return (~0, sprint("unknown mode %#ux", mode));
	}
	return (a, nil);
}

readmsg(fd: ref Sys->FD, tcp: int): (array of byte, string)
{
	if(tcp)
		return sunrpc->readmsg(fd);

	buf := array[64*1024] of byte;
	n := sys->readn(fd, buf, len buf);
	if(n < 0)
		return (nil, sprint("read: %r"));
	return (buf[:n], nil);
}

rpc(tm: ref Tnfs, rtag: int): (ref Rnfs, string)
{
if(dflag) warn("nfs-> "+tm.text());

	tm.r = ref Trpc (++xidgen, Sunrpc->Rpcversion, Nfsrpc->ProgNfs, Nfsrpc->VersNfs, tagof tm, auth, nullverf);
	err := sunrpc->writerpc(nfsfd, nil, 1, tm);
	if(err != nil)
		return (nil, err);
	buf: array of byte;
	(buf, err) = readmsg(nfsfd, 1);
	if(err != nil)
		return (nil, err);

	{
		rm: ref Rnfs;
		rm = sunrpc->parseresp(tm.r, buf, rm);
if(dflag) warn(sprint("nfs<- tag %d (sent tag %d, expecting %d)", tagof rm, tagof tm, rtag));
		if(tagof rm != rtag)
			return (nil, sprint("rpc message mismatch, expected tag %d, saw tag %d, sent %d", rtag, tagof rm, tagof tm));
		return (rm, nil);
	} exception e {
	Badrpc =>	return (nil, "badrpc: "+e.t0);
	Badproc =>	return (nil, "badproc");
	Badprocargs =>	return (nil, "badprocargs");
	}
}

pathlookup(path: string): (array of byte, ref Attr, string)
{
	fh := rootfh;
	a: ref Attr;
	err: string;
	for(l := sys->tokenize(path, "/").t1; err == nil && l != nil; l = tl l)
		(fh, a, err) = nfslookup(ref Fh (fh, nil, nil), hd l);
	return (fh, a, err);
}

pathcombine(path, elem: string): string
{
	if(elem == ".")
		return path;
	if(elem != "..")
		return path+elem+"/";
	return str->splitstrr(path, "/").t0;
}

refresh(i: int, status: int, fh: ref Fh): int
{
	if(i > 0 || status != Estale || fh.elem == nil)
		return 0;
	(nfh, nil, err) := pathlookup(fh.parent+fh.elem);
	if(err == nil) {
		fh.fh = nfh;
		return 1;
	}
	return 0;
}

nfsgetattr(fh: ref Fh): (ref Attr, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Getattr (nil, fh.fh);
		(rm, err) := rpc(tm, tagof Rnfs.Getattr);
		if(err == nil)
			pick m := rm {
			Getattr =>
				pick g := m.r {
				Ok =>	return (ref g.attr, nil);
				Fail =>
					if(refresh(i, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, err);
	}
}

nfssetattr(fh: ref Fh, sattr: Sattr): string
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Setattr (nil, fh.fh, sattr, 0, 0);
		(rm, err) := rpc(tm, tagof Rnfs.Setattr);
		if(err == nil)
			pick m := rm {
			Setattr =>
				if(refresh(i, m.status, fh))
					continue;
				if(m.status != Nfsrpc->Eok)
					err = nfsrpc->error(m.status);
			}
		return err;
	}
}

nfslookup(fh: ref Fh, elem: string): (array of byte, ref Attr, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Lookup (nil, Dirargs (fh.fh, elem));
		(rm, err) := rpc(tm, tagof Rnfs.Lookup);
		if(err == nil)
			pick m := rm {
			Lookup =>
				pick g := m.r {
				Ok =>	return (g.fh, g.fhattr, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, nil, err);
	}
}

nfsaccess(fh: ref Fh, access: int): (int, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Access (nil, fh.fh, access);
		(rm, err) := rpc(tm, tagof Rnfs.Access);
		if(err == nil)
			pick m := rm {
			Access =>
				pick g := m.r {
				Ok =>	return (g.access, nil);
				Fail =>
					if(refresh(i, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (0, err);
	}
}

nfsread(fh: ref Fh, offset: big, n: int): (array of byte, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Read (nil, fh.fh, offset, n);
		(rm, err) := rpc(tm, tagof Rnfs.Read);
		if(err == nil)
			pick m := rm {
			Read =>
				pick g := m.r {
				Ok =>	return (g.data, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, err);
	}
}

nfswrite(fh: ref Fh, offset: big, data: array of byte): (int, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Write (nil, fh.fh, offset, len data, Nfsrpc->WriteUnstable, data);
		(rm, err) := rpc(tm, tagof Rnfs.Write);
		if(err == nil)
			pick m := rm {
			Write =>
				pick g := m.r {
				Ok =>	return (g.count, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (-1, err);
	}
}


nfsmkdir(fh: ref Fh, name: string, a: Sattr): (array of byte, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Mkdir (nil, Dirargs (fh.fh, name), a);
		(rm, err) := rpc(tm, tagof Rnfs.Mkdir);
		if(err == nil)
			pick m := rm {
			Mkdir =>
				pick g := m.r {
				Ok =>	return (g.fh, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, err);
	}
}

nfscreate(fh: ref Fh, name: string, a: Sattr): (array of byte, string)
{
	i := 0;
	for(;;) {
		c := ref Createhow.Guarded (a);
		tm := ref Tnfs.Create (nil, Dirargs (fh.fh, name), c);
		(rm, err) := rpc(tm, tagof Rnfs.Create);
		if(err == nil)
			pick m := rm {
			Create =>
				pick g := m.r {
				Ok =>	return (g.fh, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, err);
	}
}

nfsreaddirplus(fh: ref Fh, cookie: big, cookieverf: array of byte): (array of Entryplus, int, array of byte, string)
{
	if(cookieverf == nil)
		cookieverf = array[8] of {* => byte 0};
	i := 0;
	for(;;) {
		tm := ref Tnfs.Readdirplus (nil, fh.fh, cookie, cookieverf, 4*1024, 4*1024);
		(rm, err) := rpc(tm, tagof Rnfs.Readdirplus);
		if(err == nil)
			pick m := rm {
			Readdirplus =>
				pick g := m.r {
				Ok =>	return (g.dir, g.eof, g.cookieverf, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, 0, nil, err);
	}
}

nfsremove(fh: ref Fh, name: string): string
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Remove (nil, Dirargs (fh.fh, name));
		(rm, err) := rpc(tm, tagof Rnfs.Remove);
		if(err == nil)
			pick m := rm {
			Remove =>
				if(refresh(i++, m.status, fh))
					continue;
				if(m.status != Nfsrpc->Eok)
					err = nfsrpc->error(m.status);
			}
		return err;
	}
}

nfsrmdir(fh: ref Fh, name: string): string
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Rmdir (nil, Dirargs (fh.fh, name));
		(rm, err) := rpc(tm, tagof Rnfs.Rmdir);
		if(err == nil)
			pick m := rm {
			Rmdir =>
				if(refresh(i++, m.status, fh))
					continue;
				if(m.status != Nfsrpc->Eok)
					err = nfsrpc->error(m.status);
			}
		return err;
	}
}

nfsrename(fh: ref Fh, name, nname: string): string
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Rename (nil, Dirargs (fh.fh, name), Dirargs (fh.fh, nname));
		(rm, err) := rpc(tm, tagof Rnfs.Rename);
		if(err == nil)
			pick m := rm {
			Rename =>
				if(refresh(i++, m.status, fh))
					continue;
				if(m.status != Nfsrpc->Eok)
					err = nfsrpc->error(m.status);
			}
		return err;
	}
}

nfsfsstat(fh: ref Fh): (ref Rfsstat.Ok, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Fsstat (nil, fh.fh);
		(rm, err) := rpc(tm, tagof Rnfs.Fsstat);
		if(err == nil)
			pick m := rm {
			Fsstat =>
				pick g := m.r {
				Ok =>	return (g, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, err);
	}
}

nfsfsinfo(fh: ref Fh): (ref Rfsinfo.Ok, string)
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Fsinfo (nil, fh.fh);
		(rm, err) := rpc(tm, tagof Rnfs.Fsinfo);
		if(err == nil)
			pick m := rm {
			Fsinfo =>
				pick g := m.r {
				Ok =>	return (g, nil);
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return (nil, err);
	}
}

nfscommit(fh: ref Fh): string
{
	i := 0;
	for(;;) {
		tm := ref Tnfs.Commit (nil, fh.fh, big 0, 0);
		(rm, err) := rpc(tm, tagof Rnfs.Commit);
		if(err == nil)
			pick m := rm {
			Commit =>
				pick g := m.r {
				Fail =>
					if(refresh(i++, g.status, fh))
						continue;
					err = nfsrpc->error(g.status);
				}
			}
		return err;
	}
}

packfsstat(f: ref Rfsstat.Ok): string
{
	s := "";
	s += sprint("tbytes %bd\n", f.tbytes);
	s += sprint("fbytes %bd\n", f.fbytes);
	s += sprint("abytes %bd\n", f.abytes);
	s += sprint("tfiles %bd\n", f.tfiles);
	s += sprint("ffiles %bd\n", f.ffiles);
	s += sprint("afiles %bd\n", f.afiles);
	s += sprint("invarsec %d\n", f.invarsec);
	return s;
}

packfsinfo(f: ref Rfsinfo.Ok): string
{
	s := "";
	s += sprint("rtmax %d\n", f.rtmax);
	s += sprint("rtpref %d\n", f.rtpref);
	s += sprint("rtmult %d\n", f.rtmult);
	s += sprint("wtmax %d\n", f.wtmax);
	s += sprint("wtpref %d\n", f.wtpref);
	s += sprint("wtmult %d\n", f.wtmult);
	s += sprint("dtpref %d\n", f.dtpref);
	s += sprint("maxfilesize %bd\n", f.maxfilesize);
	s += sprint("timedelta %d,%d\n", f.timedelta.secs, f.timedelta.nsecs);
	s += sprint("props %d\n", f.props);
	return s;
}


mnt(tcp: int, host: string, port: int, path: string, auth: Auth): (array of byte, array of int, string)
{
	addr := sprint("tcp!%s!%d", host, port);
	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		return (nil, nil, sprint("dial %q: %r", addr));
	fd := conn.dfd;

	tr := ref Trpc (++xidgen, Sunrpc->Rpcversion, Mntrpc->ProgMnt, Mntrpc->VersMnt, tagof Tmnt.Mnt, auth, auth);
	tm := ref Tmnt.Mnt (tr, path);

	err := sunrpc->writerpc(fd, nil, tcp, tm);
	if(err != nil)
		return (nil, nil, err);

	buf: array of byte;
	(buf, err) = readmsg(fd, tcp);
	if(err != nil)
		return (nil, nil, err);

	{
		rm: ref Rmnt;
		rm = sunrpc->parseresp(tm.r, buf, rm);
		pick m := rm {
		Mnt =>
			if(m.status != Mntrpc->Eok)
				return (nil, nil, sprint("mnt, error %d", m.status));
			return (m.fh, m.auths, nil);
		* =>
			return (nil, nil, "mnt, response mismatch");
		}
	} exception e {
	Parse =>	return (nil, nil, e.t0);
	Badrpc =>	return (nil, nil, e.t0);
	}
}

readsysname()
{
	n := sys->readn(sys->open("/dev/sysname", Sys->OREAD), buf := array[256] of byte, len buf);
	if(n > 0)
		sysname = string buf[:n];
}

readusers()
{
	b := bufio->open(userfile, Bufio->OREAD);
	if(b == nil)
		fail(sprint("open %q: %r", userfile));
	for(;;) {
		s := b.gets('\n');
		if(s == nil)
			break;
		if(s[len s-1] == '\n')
			s = s[:len s-1];
		t := l2a(sys->tokenize(s, ":").t1);
		if(len t < 3)
			fail(sprint("bad users line %q, need at least three tokens", s));
		user := t[0];
		id := int t[2];
		if(users.find(id) != nil)
			fail(sprint("duplicate user, id %d, names %#q and %#q: %s", id, user, users.find(id), s));
		users.add(id, user);
	}
}

readgroups()
{
	b := bufio->open(groupfile, Bufio->OREAD);
	if(b == nil)
		fail(sprint("open %q: %r", userfile));
	for(;;) {
		s := b.gets('\n');
		if(s == nil)
			break;
		if(s[len s-1] == '\n')
			s = s[:len s-1];
		t := l2a(sys->tokenize(s, ":").t1);
		if(len t < 3)
			fail(sprint("bad group line %q, need at least three tokens", s));
		group := t[0];
		id := int t[2];
		if(groups.find(id) != nil)
			fail(sprint("duplicate group, id %d, names %#q and %#q: %s", id, group, groups.find(id), s));
		groups.add(id, group);
	}
}

lookupid(t: ref Table[string], id: int): string
{
	s := t.find(id);
	if(s == nil)
		s = string id;
	return s;
}

lookupname(t: ref Table[string], name: string): int
{
	for(i := 0; i < len t.items; i++)
		for(l := t.items[i]; l != nil; l = tl l)
			if((hd l).t1 == name)
				return (hd l).t0;
	return int name;
}

isnulldir(d: Sys->Dir): int
{
	nd := sys->nulldir;
	return d.name == nd.name &&
		d.uid == nd.uid &&
		d.gid == nd.gid &&
		d.muid == nd.muid &&
		d.mode == nd.mode &&
		d.atime == nd.atime &&
		d.mtime == nd.mtime &&
		d.length == nd.length;
}

# bad name for walk?
isbadname(s: string): int
{
	if(s == nil)
		return 1;
	for(i := 0; i < len s; i++)
		if(s[i] == '/')
			return 1;
	return 0;
}

l2aint(l: list of int): array of int
{
	a := array[len l] of int;
	i := 0;
	for(; l != nil; l = tl l)
		a[i++] = hd l;
	return a;
}

say(s: string)
{
	if(dflag)
		warn(s);
}

fail(s: string)
{
	warn(s);
	killgrp(pid());
	raise "fail:"+s;
}
