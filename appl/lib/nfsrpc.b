implement Nfsrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";
	sunrpc: Sunrpc;
	gbool, g32, g64, gopaque, gopaquefixed, gstr, pbool, p32, p64, popaque, popaquefixed, pstr: import sunrpc;
	Parse, Badprog, Badproc, Badprocargs, Badrpc: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "nfsrpc.m";

Mnull,
Mgetattr,
Msetattr,
Mlookup,
Maccess,
Mreadlink,
Mread,
Mwrite,
Mcreate,
Mmkdir,
Msymlink,
Mmknod,
Mremove,
Mrmdir,
Mrename,
Mlink,
Mreaddir,
Mreaddirplus,
Mfsstat,
Mfsinfo,
Mpathconf,
Mcommit: con iota;


init()
{
	sys = load Sys Sys->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
}

Tnfs.unpack(m: ref Trpc, buf: array of byte): ref Tnfs raises (Badrpc, Badprog, Badproc, Badprocargs)
{
	if(m.prog != ProgNfs)
		raise Badprog;
	if(m.vers != VersNfs) {
		nullverf: Auth; # will be fixed by caller
		raise Badrpc(sprint("bad Tnfs, version %d", m.vers), nil, ref Rrpc.Progmismatch (m.xid, nullverf, VersNfs, VersNfs));
	}

	{
		tt: ref Tnfs;
		o := 0;
		case m.proc {
		Mnull =>
			tt = ref Tnfs.Null;
		Mgetattr =>
			tt = t := ref Tnfs.Getattr;
			(t.fh, o) = gfilehandle(buf, o);
		Msetattr =>
			tt = t := ref Tnfs.Setattr;
			(t.fh, o) = gfilehandle(buf, o);
			(t.newattr, o) = gsattr(buf, o);
			(t.haveguard, o) = gbool(buf, o);
			if(t.haveguard) {
				(t.guardctime, o) = g32(buf, o);
				(nil, o) = g32(buf, o);
			}
		Mlookup =>
			tt = t := ref Tnfs.Lookup;
			(t.where, o) = gdirargs(buf, o);
		Maccess =>
			tt = t := ref Tnfs.Access;
			(t.fh, o) = gfilehandle(buf, o);
			(t.access, o) = g32(buf, o);
			if(t.access&~ACmask)
				raise Parse(sprint("Tnfs.Access, bad bits in access: 0x%x", t.access&~ACmask));
		Mreadlink =>
			tt = t := ref Tnfs.Readlink;
			(t.fh, o) = gfilehandle(buf, o);
		Mread =>
			tt = t := ref Tnfs.Read;
			(t.fh, o) = gfilehandle(buf, o);
			(t.offset, o) = g64(buf, o);
			(t.count, o) = g32(buf, o);
		Mwrite =>
			tt = t := ref Tnfs.Write;
			(t.fh, o) = gfilehandle(buf, o);
			(t.offset, o) = g64(buf, o);
			(t.count, o) = g32(buf, o);
			(t.stablehow, o) = g32(buf, o);
			case t.stablehow {
			WriteUnstable or
			WriteDatasync or
			WriteFilesync =>
				;
			* =>
				raise Parse(sprint("Tnfs.Write, bad stablehow %d", t.stablehow));
			}
			(t.data, o) = gopaque(buf, o, -1);
			if(t.count != len t.data)
				raise Parse(sprint("Tnfs.Write, count %d != len data %d", t.count, len t.data));
		Mcreate =>
			tt = t := ref Tnfs.Create;
			(t.where, o) = gdirargs(buf, o);
			createhow: int;
			(createhow, o) = g32(buf, o);
			case createhow {
			CreateUnchecked =>
				t.createhow = c := ref Createhow.Unchecked;
				(c.attr, o) = gsattr(buf, o);
			CreateGuarded =>
				t.createhow = c := ref Createhow.Guarded;
				(c.attr, o) = gsattr(buf, o);
			CreateExclusive =>
				t.createhow = c := ref Createhow.Exclusive;
				(c.createverf, o) = gopaquefixed(buf, o, Verfsize);
			* =>
				raise Parse(sprint("Tnfs.Create, bad createhow %d", createhow));
			}
		Mmkdir =>
			tt = t := ref Tnfs.Mkdir;
			(t.where, o) = gdirargs(buf, o);
			(t.attr, o) = gsattr(buf, o);
		Msymlink =>
			tt = t := ref Tnfs.Symlink;
			(t.where, o) = gdirargs(buf, o);
			(t.attr, o) = gsattr(buf, o);
			(t.path, o) = gstr(buf, o, -1); # xxx no max?
		Mmknod =>
			tt = t := ref Tnfs.Mknod;
			(t.where, o) = gdirargs(buf, o);
			nodetype: int;
			(nodetype, o) = g32(buf, o);
			nn: ref Nod;
			case nodetype {
			FTreg =>
				nn = ref Nod.Reg;
			FTdir =>
				nn = ref Nod.Dir;
			FTlnk =>
				nn = ref Nod.Lnk;
			FTblk =>
				nn = n := ref Nod.Blk;
				(n.attr, o) = gsattr(buf, o);
				(n.spec.major, o) = g32(buf, o);
				(n.spec.minor, o) = g32(buf, o);
			FTchr =>
				nn = n := ref Nod.Chr;
				(n.attr, o) = gsattr(buf, o);
				(n.spec.major, o) = g32(buf, o);
				(n.spec.minor, o) = g32(buf, o);
			FTsock =>
				nn = n := ref Nod.Sock;
				(n.attr, o) = gsattr(buf, o);
			FTfifo =>
				nn = n := ref Nod.Fifo;
				(n.attr, o) = gsattr(buf, o);
			}
			t.node = nn;
		Mremove =>
			tt = t := ref Tnfs.Remove;
			(t.where, o) = gdirargs(buf, o);
		Mrmdir =>
			tt = t := ref Tnfs.Rmdir;
			(t.where, o) = gdirargs(buf, o);
		Mrename =>
			tt = t := ref Tnfs.Rename;
			(t.owhere, o) = gdirargs(buf, o);
			(t.nwhere, o) = gdirargs(buf, o);
		Mlink =>
			tt = t := ref Tnfs.Link;
			(t.fh, o) = gfilehandle(buf, o);
			(t.link, o) = gdirargs(buf, o);
		Mreaddir =>
			tt = t := ref Tnfs.Readdir;
			(t.fh, o) = gfilehandle(buf, o);
			(t.cookie, o) = g64(buf, o);
			(t.cookieverf, o) = gopaquefixed(buf, o, Verfsize);
			(t.count, o) = g32(buf, o);
		Mreaddirplus =>
			tt = t := ref Tnfs.Readdirplus;
			(t.fh, o) = gfilehandle(buf, o);
			(t.cookie, o) = g64(buf, o);
			(t.cookieverf, o) = gopaquefixed(buf, o, Verfsize);
			(t.dircount, o) = g32(buf, o);
			(t.maxcount, o) = g32(buf, o);
		Mfsstat =>
			tt = t := ref Tnfs.Fsstat;
			(t.rootfh, o) = gfilehandle(buf, o);
		Mfsinfo =>
			tt = t := ref Tnfs.Fsinfo;
			(t.rootfh, o) = gfilehandle(buf, o);
		Mpathconf =>
			tt = t := ref Tnfs.Pathconf;
			(t.fh, o) = gfilehandle(buf, o);
		Mcommit =>
			tt = t := ref Tnfs.Commit;
			(t.fh, o) = gfilehandle(buf, o);
			(t.offset, o) = g64(buf, o);
			(t.count, o) = g32(buf, o);
		* =>
			raise Badproc;
		}
		if(o != len buf)
			raise Badprocargs(sprint("bad Tnfs, leftover bytes, o %d != len buf %d", o, len buf));
		tt.r = m;
		return tt;
	} exception e {
	Parse =>
		raise Badprocargs(e);
	Badproc =>
		raise;
	Badprocargs =>
		raise;
	}
}

wheretext(d: Dirargs): string
{
	return sprint("fh %s name %q", hex(d.fh), d.name);
}

tnfstagnames := array[] of {
"Null", "Getattr", "Setattr", "Lookup", "Access", "Readlink", "Read", "Write",
"Create", "Mkdir", "Symlink", "Mknod", "Remove", "Rmdir", "Rename", "Link",
"Readdir", "Readdirplus", "Fsstat", "Fsinfo", "Pathconf", "Commit",
};
Tnfs.text(mm: self ref Tnfs): string
{
	s := sprint("Tnfs.%s(", tnfstagnames[tagof mm]);
	pick m := mm {
	Getattr =>	s += "fh "+hex(m.fh);
	Setattr =>	s += "fh "+hex(m.fh);
	Lookup =>	s += wheretext(m.where);
	Access =>	s += "fh "+hex(m.fh)+sprint(" access 0x%x", m.access);
	Readlink =>	s += "fh "+hex(m.fh);
	Read =>		s += "fh "+hex(m.fh)+sprint(" offset %bd count %d", m.offset, m.count);
	Write =>	s += "fh "+hex(m.fh)+sprint(" offset %bd count %d", m.offset, m.count);
	Create =>	s += wheretext(m.where);
	Mkdir =>	s += wheretext(m.where);
	Symlink =>	s += wheretext(m.where)+sprint(" path %q", m.path);
	Mknod =>	s += wheretext(m.where);
	Remove =>	s += wheretext(m.where);
	Rmdir =>	s += wheretext(m.where);
	Rename =>	s += "old "+wheretext(m.owhere)+" new "+wheretext(m.nwhere);
	Link =>		s += "fh "+hex(m.fh)+" "+wheretext(m.link);
	Readdir =>	s += "fh "+hex(m.fh)+sprint(" count %d", m.count);
	Readdirplus =>	s += "fh "+hex(m.fh)+sprint(" dircount %d maxcount %d",m.dircount, m.maxcount);
	Fsstat =>	s += "fh "+hex(m.rootfh);
	Fsinfo =>	s += "fh "+hex(m.rootfh);
	Pathconf =>	s += "fh "+hex(m.fh);
	Commit =>	s += "fh "+hex(m.fh)+sprint(" offset %bd count %d", m.offset, m.count);;
	}
	s += ")";
	return s;
}

Rnfs.size(mm: self ref Rnfs): int
{
	return mm.pack(nil, 0);
}

Rnfs.pack(mm: self ref Rnfs, buf: array of byte, o: int): int
{
	o = mm.m.pack(buf, o);
	pick m := mm {
	Null =>
		;
	Getattr =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pattr(buf, o, r.attr);
		Fail =>
			o = p32(buf, o, r.status);
		}
	Setattr =>
		o = p32(buf, o, m.status);
		o = pweakdata(buf, o, m.weak);
	Lookup =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = popaque(buf, o, r.fh);
			o = pboolattr(buf, o, r.fhattr);
			o = pboolattr(buf, o, r.dirattr);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.dirattr);
		}
	Access =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			if(r.access&~ACmask)
				raise sprint("Rnfs.Access, bad bits in access: 0x%x", r.access&~ACmask);
			o = p32(buf, o, r.access);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Readlink =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			o = pstr(buf, o, r.path);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Read =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			o = p32(buf, o, r.count);
			o = p32(buf, o, r.eof);
			o = popaque(buf, o, r.data);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Write =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pweakdata(buf, o, r.weak);
			o = p32(buf, o, r.count);
			case r.stable {
			WriteUnstable or
			WriteDatasync or
			WriteFilesync =>
				;
			* =>
				raise sprint("bad Rnfs.Write.Ok, unknown stable %d", r.stable);
			}
			o = p32(buf, o, r.stable);
			if(len r.verf != Verfsize)
				raise "bad Rnfs.Write";
			o = popaquefixed(buf, o, r.verf);
		Fail =>
			o = p32(buf, o, r.status);
			o = pweakdata(buf, o, r.weak);
		}
	Create or
	Mkdir or
	Symlink or
	Mknod =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pbool(buf, o, r.fh != nil);
			if(r.fh != nil)
				o = popaque(buf, o, r.fh);
			o = pboolattr(buf, o, r.attr);
			o = pweakdata(buf, o, r.weak);
		Fail =>
			o = p32(buf, o, r.status);
			o = pweakdata(buf, o, r.weak);
		}
	Remove or
	Rmdir =>
		o = p32(buf, o, m.status);
		o = pweakdata(buf, o, m.weak);
	Rename =>
		o = p32(buf, o, m.status);
		o = pweakdata(buf, o, m.fromdir);
		o = pweakdata(buf, o, m.todir);
	Link =>
		o = p32(buf, o, m.status);
		o = pboolattr(buf, o, m.attr);
		pweakdata(buf, o, m.weak);
	Readdir =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			if(len r.cookieverf != Verfsize)
				raise "bad Rnfs.Readdir";
			o = popaquefixed(buf, o, r.cookieverf);
			for(i := 0; i < len r.dir; i++) {
				o = pbool(buf, o, 1);
				e := r.dir[i];
				o = p64(buf, o, e.id);
				o = pstr(buf, o, e.name);
				o = p64(buf, o, e.cookie);
			}
			o = pbool(buf, o, 0);
			o = pbool(buf, o, r.eof);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Readdirplus =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			if(len r.cookieverf != Verfsize)
				raise "bad Rnfs.Readdirplus";
			o = popaquefixed(buf, o, r.cookieverf);
			for(i := 0; i < len r.dir; i++) {
				o = p32(buf, o, 1);
				e := r.dir[i];
				o = p64(buf, o, e.id);
				o = pstr(buf, o, e.name);
				o = p64(buf, o, e.cookie);
				o = pboolattr(buf, o, e.attr);
				o = pbool(buf, o, e.fh != nil);
				if(e.fh != nil)
					o = popaque(buf, o, e.fh);
			}
			o = p32(buf, o, 0);
			o = pbool(buf, o, r.eof);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Fsstat =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			o = p64(buf, o, r.tbytes);
			o = p64(buf, o, r.fbytes);
			o = p64(buf, o, r.abytes);
			o = p64(buf, o, r.tfiles);
			o = p64(buf, o, r.ffiles);
			o = p64(buf, o, r.afiles);
			o = p32(buf, o, r.invarsec);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Fsinfo =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			o = p32(buf, o, r.rtmax);
			o = p32(buf, o, r.rtpref);
			o = p32(buf, o, r.rtmult);
			o = p32(buf, o, r.wtmax);
			o = p32(buf, o, r.wtpref);
			o = p32(buf, o, r.wtmult);
			o = p32(buf, o, r.dtpref);
			o = p64(buf, o, r.maxfilesize);
			o = p32(buf, o, r.timedelta.secs);
			o = p32(buf, o, r.timedelta.nsecs);
			if(r.props&~FSFmask)
				raise sprint("Rnfs.Fsinfo.Ok, bad bits in props, 0x%x", r.props&~FSFmask);
			o = p32(buf, o, r.props);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Pathconf =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			o = p32(buf, o, r.linkmax);
			o = p32(buf, o, r.namemax);
			o = p32(buf, o, r.notrunc);
			o = p32(buf, o, r.chownrestr);
			o = p32(buf, o, r.caseinsens);
			o = p32(buf, o, r.casepres);
		Fail =>
			o = p32(buf, o, r.status);
			o = pboolattr(buf, o, r.attr);
		}
	Commit =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pweakdata(buf, o, r.weak);
			if(len r.writeverf != Verfsize)
				raise "bad Rnfs.Commit";
			o = popaquefixed(buf, o, r.writeverf);
		Fail =>
			o = p32(buf, o, r.status);
			o = pweakdata(buf, o, r.weak);
		}
	}
	return o;
}

pboolattr(buf: array of byte, o: int, a: ref Attr): int
{
	o = pbool(buf, o, a != nil);
	if(a != nil)
		o = pattr(buf, o, *a);
	return o;
}

pattr(buf: array of byte, o: int, a: Attr): int
{
	case a.ftype {
	FTreg or
	FTdir or
	FTblk or
	FTchr or
	FTlnk or
	FTsock or
	FTfifo =>
		;
	* =>
		raise sprint("bad file type %d, in attributes", a.ftype);
	}
	o = p32(buf, o, a.ftype);
	o = p32(buf, o, a.mode);
	o = p32(buf, o, a.nlink);
	o = p32(buf, o, a.uid);
	o = p32(buf, o, a.gid);
	o = p64(buf, o, a.size);
	o = p64(buf, o, a.used);
	o = p32(buf, o, a.rdev.major);
	o = p32(buf, o, a.rdev.minor);
	o = p64(buf, o, a.fsid);
	o = p64(buf, o, a.fileid);
	o = p32(buf, o, a.atime);
	o = p32(buf, o, 0);
	o = p32(buf, o, a.mtime);
	o = p32(buf, o, 0);
	o = p32(buf, o, a.ctime);
	o = p32(buf, o, 0);
	return o;
}

pweakattr(buf: array of byte, o: int, w: ref Weakattr): int
{
	o = p64(buf, o, w.size);
	o = p32(buf, o, w.mtime);
	o = p32(buf, o, 0);
	o = p32(buf, o, w.ctime);
	o = p32(buf, o, 0);
	return o;
}

pweakdata(buf: array of byte, o: int, w: Weakdata): int
{
	o = pbool(buf, o, w.before != nil);
	if(w.before != nil)
		o = pweakattr(buf, o, w.before);
	o = pbool(buf, o, w.after != nil);
	if(w.after != nil)
		o = pattr(buf, o, *w.after);
	return o;
		
}

gsattr(buf: array of byte, o: int): (Sattr, int) raises Parse
{
	{
		a: Sattr;
		(a.setmode, o) = gbool(buf, o);
		if(a.setmode)
			(a.mode, o) = g32(buf, o);
		(a.setuid, o) = gbool(buf, o);
		if(a.setuid)
			(a.uid, o) = g32(buf, o);
		(a.setgid, o) = gbool(buf, o);
		if(a.setgid)
			(a.gid, o) = g32(buf, o);
		(a.setsize, o) = gbool(buf, o);
		if(a.setsize)
			(a.size, o) = g64(buf, o);
		(a.setatime, o) = g32(buf, o);
		case a.setatime {
		SETdontchange or
		SETtoservertime =>
			;
		SETtoclienttime =>
			(a.atime, o)	= g32(buf, o);
			(nil, o)	= g32(buf, o);
		* =>
			raise Parse(sprint("bad value 0x%x for sattr.setatime", a.setatime));
		}
		(a.setmtime, o) = g32(buf, o);
		case a.setmtime {
		SETdontchange or
		SETtoservertime =>
			;
		SETtoclienttime =>
			(a.mtime, o)	= g32(buf, o);
			(nil, o)	= g32(buf, o);
		* =>
			raise Parse(sprint("bad value 0x%x for sattr.setmtime", a.setmtime));
		}
		return (a, o);
	} exception e {
	Parse => raise Parse("gsattr: "+e);
	}
}

gdirargs(buf: array of byte, o: int): (Dirargs, int) raises Parse
{
	{
		d: Dirargs;
		(d.fh, o) = gfilehandle(buf, o);
		(d.name, o) = gstr(buf, o, -1); # xxx no max?
		return (d, o);
	} exception e {
	Parse => raise Parse("gdirargs: "+e);
	}
}

gfilehandle(buf: array of byte, o: int): (array of byte, int) raises Parse
{
	{
		return gopaque(buf, o, Filehandlesizemax);
	} exception e {
	Parse => raise Parse("gfilehandle: "+e);
	}
}

hex(d: array of byte): string
{
	s := "";
	for(i := 0; i < len d; i++)
		s += sprint("%02x", int d[i]);
	return s;
}
