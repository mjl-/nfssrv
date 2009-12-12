implement Nfsrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";
	sunrpc: Sunrpc;
	gbool, g32, g64, gopaque, gopaquefixed, gstr, pbool, p32, p64, popaque, popaquefixed, pstr, pboolopaque: import sunrpc;
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

dflag = 0;

init()
{
	sys = load Sys Sys->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
}

error(v: int): string
{
	case v {
	Eok =>		return "success";
	Eperm =>	return "permission denied";
	Enoent =>	return "file does not exist";
	Eio =>		return "i/o error";
	Enxio =>	return "i/o error, no such device";
	Eacces =>	return "permission denied";
	Eexist =>	return "file already exists";
	Exdev =>	return "bad argument, cross-device hard link";
	Enodev =>	return "file does not exist, no such device";
	Enotdir =>	return "not a directory";
	Eisdir =>	return "bad argument, is a directory";
	Einval =>	return "bad argument";
	Efbig =>	return "file too big";
	Enospc =>	return "no space left";
	Erofs =>	return "permission denied, read-only file system";
	Emlink =>	return "too many hard links";
	Enametoolong =>	return "bad argument, name too long";
	Enotempty =>	return "directory not empty";
	Edquot =>	return "quota exceeded";
	Estale =>	return "stale nfs file handle";
	Eremote =>	return "too many levels of remote";
	Ebadhandle =>	return "invalid nfs file handle";
	Enotsync =>	return "synchronization mismatch";
	Ebadcookie =>	return "bad cookie";
	Enotsupp =>	return "operation not supported";
	Etoosmall =>	return "buffer or request too small";
	Eserverfault =>	return "server fault";
	Ebadtype =>	return "bad type, not supported";
	Ejukebox =>	return "slow jukebox, try again";
	* =>
		return sprint("error, %d", v);
	}
}

Time.text(t: self Time): string
{
	return sprint("%d,%d", t.secs, t.nsecs);
}

Attr.text(w: self ref Attr): string
{
	if(w == nil)
		return "nil";
	return sprint("Attr(ftype %d, mode %uo, nlink %d, uid %d, gid %d, size %bud, used %bud, rdev %d,%d, fsid %bux, fileid %bux, atime %d, mtime %d, ctime %d)", w.ftype, w.mode, w.nlink, w.uid, w.gid, w.size, w.used, w.rdev.major, w.rdev.minor, w.fsid, w.fileid, w.atime, w.mtime, w.ctime);
}

Weakattr.text(w: self ref Weakattr): string
{
	if(w == nil)
		return "nil";
	return sprint("Weakattr (size %bud, mtime %d, ctime %d)", w.size, w.mtime, w.ctime);
}

Weakdata.text(w: self Weakdata): string
{
	return sprint("Weakdata (before %s, after %s)", w.before.text(), w.after.text());
}

Sattr.text(s: self Sattr): string
{
	r := "";
	if(s.setmode) r += sprint(", mode %uo", s.mode);
	if(s.setuid) r += sprint(", uid %d", s.uid);
	if(s.setgid) r += sprint(", gid %d", s.gid);
	if(s.setsize) r += sprint(", size %bud", s.size);
	if(s.setatime) r += sprint(", setatime %d %d", s.setatime, s.atime);
	if(s.setmtime) r += sprint(", setmtime %d %d", s.setmtime, s.mtime);
	if(r != nil)
		r = r[1:];
	return "Sattr("+r+")";
}

Dirargs.text(d: self Dirargs): string
{
	return sprint("Dirargs(fh %s, name %q)", hex(d.fh), d.name);
}

nodtagnames := array[] of {"Chr", "Blk", "Sock", "Fifo", "Reg", "Dir", "Lnk"};
Nod.text(nn: self ref Nod): string
{
	s := sprint("Nod.%s(", nodtagnames[tagof nn]);
	pick n := nn {
	Chr or
	Blk =>	s += sprint("attr %s, spec %d,%d", n.attr.text(), n.spec.major, n.spec.minor);
	Sock or
	Fifo =>	s += sprint("attr %s", n.attr.text());
	Reg or
	Dir or
	Lnk =>	;
	* =>
		raise "missing case";
	}
	s += ")";
	return s;
}

createhowtagnames := array[] of {"Unchecked", "Guarded", "Exclusive"};
Createhow.text(nn: self ref Createhow): string
{
	s := sprint("Createhow.%s(", createhowtagnames[tagof nn]);
	pick n := nn {
	Unchecked or
	Guarded =>	s += sprint("attr %s", n.attr.text());
	Exclusive =>	s += sprint("createverf %bux", n.createverf);
	}
	s += ")";
	return s;
}

Entry.text(e: self Entry): string
{
	return sprint("Entry(id %bux, name %q, cookie %bd)", e.id, e.name, e.cookie);
}

Entryplus.text(e: self Entryplus): string
{
	return sprint("Entryplus(id %bux, name %q, cookie %bd, attr %s, fh %s)", e.id, e.name, e.cookie, e.attr.text(), hex(e.fh));
}


Tnfs.size(m: self ref Tnfs): int
{
	return m.pack(nil, 0);
}

Tnfs.pack(mm: self ref Tnfs, buf: array of byte, o: int): int
{
	o = mm.r.pack(buf, o);
	pick m := mm {
	Null =>
		;
	Getattr =>
		o = popaque(buf, o, m.fh);
	Setattr =>
		o = popaque(buf, o, m.fh);
		o = psattr(buf, o, m.newattr);
		o = pbool(buf, o, m.haveguard);
		if(m.haveguard) {
			o = p32(buf, o, m.guardctime);
			o = p32(buf, o, 0);
		}
	Lookup =>
		o = pdirargs(buf, o, m.where);
	Access =>
		o = popaque(buf, o, m.fh);
		o = p32(buf, o, m.access);
	Readlink =>
		o = popaque(buf, o, m.fh);
	Read =>
		o = popaque(buf, o, m.fh);
		o = p64(buf, o, m.offset);
		o = p32(buf, o, m.count);
	Write =>
		o = popaque(buf, o, m.fh);
		o = p64(buf, o, m.offset);
		o = p32(buf, o, m.count);
		o = p32(buf, o, m.stablehow);
		o = popaque(buf, o, m.data);
	Create =>
		o = pdirargs(buf, o, m.where);
		o = pcreatehow(buf, o, m.createhow);
	Mkdir =>
		o = pdirargs(buf, o, m.where);
		o = psattr(buf, o, m.attr);
	Symlink =>
		o = pdirargs(buf, o, m.where);
		o = psattr(buf, o, m.attr);
		o = pstr(buf, o, m.path);
	Mknod =>
		o = pdirargs(buf, o, m.where);
		o = pnod(buf, o, m.node);
	Remove =>
		o = pdirargs(buf, o, m.where);
	Rmdir =>
		o = pdirargs(buf, o, m.where);
	Rename =>
		o = pdirargs(buf, o, m.owhere);
		o = pdirargs(buf, o, m.nwhere);
	Link =>
		o = popaque(buf, o, m.fh);
		o = pdirargs(buf, o, m.link);
	Readdir =>
		o = popaque(buf, o, m.fh);
		o = p64(buf, o, m.cookie);
		o = p64(buf, o, m.cookieverf);
		o = p32(buf, o, m.count);
	Readdirplus =>
		o = popaque(buf, o, m.fh);
		o = p64(buf, o, m.cookie);
		o = p64(buf, o, m.cookieverf);
		o = p32(buf, o, m.dircount);
		o = p32(buf, o, m.maxcount);
	Fsstat =>
		o = popaque(buf, o, m.rootfh);
	Fsinfo =>
		o = popaque(buf, o, m.rootfh);
	Pathconf =>
		o = popaque(buf, o, m.fh);
	Commit =>
		o = popaque(buf, o, m.fh);
		o = p64(buf, o, m.offset);
		o = p32(buf, o, m.count);
	* =>
		raise "missing case";
	}
	return o;
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
				raise Parse(sprint("Tnfs.Access, bad bits in access: %#ux", t.access&~ACmask));
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
			(t.createhow, o) = gcreatehow(buf, o);
		Mmkdir =>
			tt = t := ref Tnfs.Mkdir;
			(t.where, o) = gdirargs(buf, o);
			(t.attr, o) = gsattr(buf, o);
		Msymlink =>
			tt = t := ref Tnfs.Symlink;
			(t.where, o) = gdirargs(buf, o);
			(t.attr, o) = gsattr(buf, o);
			(t.path, o) = gstr(buf, o, -1);
		Mmknod =>
			tt = t := ref Tnfs.Mknod;
			(t.where, o) = gdirargs(buf, o);
			(t.node, o) = gnod(buf, o);
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
			(t.cookieverf, o) = g64(buf, o);
			(t.count, o) = g32(buf, o);
		Mreaddirplus =>
			tt = t := ref Tnfs.Readdirplus;
			(t.fh, o) = gfilehandle(buf, o);
			(t.cookie, o) = g64(buf, o);
			(t.cookieverf, o) = g64(buf, o);
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
	Access =>	s += "fh "+hex(m.fh)+sprint(", access %#ux", m.access);
	Readlink =>	s += "fh "+hex(m.fh);
	Read =>		s += "fh "+hex(m.fh)+sprint(", offset %bud, count %d", m.offset, m.count);
	Write =>	s += "fh "+hex(m.fh)+sprint(", offset %bud, count %d", m.offset, m.count);
	Create =>	s += wheretext(m.where);
	Mkdir =>	s += wheretext(m.where);
	Symlink =>	s += wheretext(m.where)+sprint(", path %q", m.path);
	Mknod =>	s += wheretext(m.where);
	Remove =>	s += wheretext(m.where);
	Rmdir =>	s += wheretext(m.where);
	Rename =>	s += "old "+wheretext(m.owhere)+", new "+wheretext(m.nwhere);
	Link =>		s += "fh "+hex(m.fh)+" "+wheretext(m.link);
	Readdir =>	s += "fh "+hex(m.fh)+sprint(", cookie %bux, verf %bux, count %d", m.cookie, m.cookieverf, m.count);
	Readdirplus =>	s += "fh "+hex(m.fh)+sprint(", cookie %bux, verf %bux, dircount %d, maxcount %d", m.cookie, m.cookieverf, m.dircount, m.maxcount);
	Fsstat =>	s += "fh "+hex(m.rootfh);
	Fsinfo =>	s += "fh "+hex(m.rootfh);
	Pathconf =>	s += "fh "+hex(m.fh);
	Commit =>	s += "fh "+hex(m.fh)+sprint(", offset %bud, count %d", m.offset, m.count);;
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
				raise sprint("Rnfs.Access, bad bits in access: %#ux", r.access&~ACmask);
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
			o = p64(buf, o, r.verf);
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
		o = pweakdata(buf, o, m.weak);
	Readdir =>
		pick r := m.r {
		Ok =>
			o = p32(buf, o, Eok);
			o = pboolattr(buf, o, r.attr);
			o = p64(buf, o, r.cookieverf);
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
			o = p64(buf, o, r.cookieverf);
			for(i := 0; i < len r.dir; i++) {
				o = p32(buf, o, 1);
				e := r.dir[i];
				o = p64(buf, o, e.id);
				o = pstr(buf, o, e.name);
				o = p64(buf, o, e.cookie);
				o = pboolattr(buf, o, e.attr);
				o = pboolopaque(buf, o, e.fh);
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
				raise sprint("Rnfs.Fsinfo.Ok, bad bits in props, %#ux", r.props&~FSFmask);
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
			o = p64(buf, o, r.writeverf);
		Fail =>
			o = p32(buf, o, r.status);
			o = pweakdata(buf, o, r.weak);
		}
	}
	return o;
}

Rnfs.unpack(tm: ref Sunrpc->Trpc, rm: ref Sunrpc->Rrpc, buf: array of byte): ref Rnfs raises (Badrpc, Badproc, Badprocargs)
{
	{
		o := 0;
		r: ref Rnfs;
		case tm.proc {
		Mnull =>
			r = ref Rnfs.Null (rm);
		Mgetattr =>
			status: int;
			(status, o) = g32(buf, o);
			m: ref Rgetattr;
			if(status == Eok) {
				m = mm := ref Rgetattr.Ok;
				(mm.attr, o) = gattr(buf, o);
			} else
				m = ref Rgetattr.Fail (status);
			r = ref Rnfs.Getattr (rm, m);

		Msetattr =>
			r = rr := ref Rnfs.Setattr;
			r.m = rm;
			(rr.status, o) = g32(buf, o);
			(rr.weak, o) = gweakdata(buf, o);
		Mlookup =>
			status: int;
			(status, o) = g32(buf, o);
			if(status == Eok) {
				rr := ref Rlookup.Ok;
				(rr.fh, o) = gfilehandle(buf, o);
				(rr.fhattr, o) = gboolattr(buf, o);
				(rr.dirattr, o) = gboolattr(buf, o);
				r = ref Rnfs.Lookup (rm, rr);
			} else {
				rr := ref Rlookup.Fail (status, nil);
				(rr.dirattr, o) = gboolattr(buf, o);
				r = ref Rnfs.Lookup (rm, rr);
			}

		Maccess =>
			status: int;
			(status, o) = g32(buf, o);
			a: ref Attr;
			(a, o) = gboolattr(buf, o);
			if(status == Eok) {
				rr := ref Raccess.Ok;
				rr.attr = a;
				(rr.access, o) = g32(buf, o);
				r = ref Rnfs.Access (rm, rr);
			} else
				r = ref Rnfs.Access (rm, ref Raccess.Fail (status, a));

		Mreadlink =>
			status: int;
			(status, o) = g32(buf, o);
			a: ref Attr;
			(a, o) = gboolattr(buf, o);
			if(status == Eok) {
				rr := ref Rreadlink.Ok;
				rr.attr = a;
				(rr.path, o) = gstr(buf, o, -1);
				r = ref Rnfs.Readlink (rm, rr);
			} else
				r = ref Rnfs.Readlink (rm, ref Rreadlink.Fail (status, a));
		Mread =>
			status: int;
			(status, o) = g32(buf, o);
			a: ref Attr;
			(a, o) = gboolattr(buf, o);
			if(status == Eok) {
				rr := ref Rread.Ok;
				rr.attr = a;
				(rr.count, o) = g32(buf, o);
				(rr.eof, o) = g32(buf, o);
				(rr.data, o) = gopaque(buf, o, -1);
				if(rr.count != len rr.data)
					raise Badprocargs(sprint("read's count (%d) does not match length of data (%d)", rr.count, len rr.data));
				r = ref Rnfs.Read (rm, rr);
			} else 
				r = ref Rnfs.Read (rm, ref Rread.Fail (status, a));
		Mwrite =>
			status: int;
			(status, o) = g32(buf, o);
			wd: Weakdata;
			(wd, o) = gweakdata(buf, o);
			if(status == Eok) {
				rr := ref Rwrite.Ok;
				rr.weak = wd;
				(rr.count, o) = g32(buf, o);
				(rr.stable, o) = g32(buf, o);
				(rr.verf, o) = g64(buf, o);
				r = ref Rnfs.Write (rm, rr);
			} else
				r = ref Rnfs.Write (rm, ref Rwrite.Fail (status, wd));
		Mcreate or
		Mmkdir or
		Msymlink or
		Mmknod =>
			status: int;
			(status, o) = g32(buf, o);
			cc: ref Rchange;
			if(status == Eok) {
				b: int;
				cc = c := ref Rchange.Ok;
				(b, o) = g32(buf, o);
				if(b)
					(c.fh, o) = gfilehandle(buf, o);
				(c.attr, o) = gboolattr(buf, o);
				(c.weak, o) = gweakdata(buf, o);
			} else {
				cc = c := ref Rchange.Fail;
				c.status = status;
				(c.weak, o) = gweakdata(buf, o);
			}
			case tm.proc {
			Mcreate =>	r = ref Rnfs.Create (rm, cc);
			Mmkdir =>	r = ref Rnfs.Mkdir (rm, cc);
			Msymlink =>	r = ref Rnfs.Symlink (rm, cc);
			Mmknod =>	r = ref Rnfs.Mknod (rm, cc);
			}
		Mremove =>
			status: int;
			(status, o) = g32(buf, o);
			r = rr := ref Rnfs.Remove;
			rr.m = rm;
			rr.status = status;
			(rr.weak, o) = gweakdata(buf, o);
		Mrmdir =>
			status: int;
			(status, o) = g32(buf, o);
			r = rr := ref Rnfs.Rmdir;
			rr.m = rm;
			rr.status = status;
			(rr.weak, o) = gweakdata(buf, o);
		Mrename =>
			status: int;
			(status, o) = g32(buf, o);
			r = rr := ref Rnfs.Rename;
			rr.m = rm;
			rr.status = status;
			(rr.fromdir, o) = gweakdata(buf, o);
			(rr.todir, o) = gweakdata(buf, o);
		Mlink =>
			status: int;
			(status, o) = g32(buf, o);
			r = rr := ref Rnfs.Link;
			rr.m = rm;
			(rr.attr, o) = gboolattr(buf, o);
			(rr.weak, o) = gweakdata(buf, o);
		Mreaddir =>
			status: int;
			(status, o) = g32(buf, o);
			a: ref Attr;
			(a, o) = gboolattr(buf, o);
			if(status == Eok) {
				rr := ref Rreaddir.Ok;
				rr.attr = a;
				(rr.cookieverf, o) = g64(buf, o);
				l: list of Entry;
				for(;;) {
					more: int;
					(more, o) = g32(buf, o);
					if(more == 0)
						break;
					e: Entry;
					(e.id, o) = g64(buf, o);
					(e.name, o) = gstr(buf, o, -1);
					(e.cookie, o) = g64(buf, o);
					l = e::l;
				}
				dirs := array[len l] of Entry;
				i := len dirs-1;
				for(; l != nil; l = tl l)
					dirs[i--] = hd l;
				rr.dir = dirs;
				(rr.eof, o) = g32(buf, o);
				r = ref Rnfs.Readdir (rm, rr);
			} else
				r = ref Rnfs.Readdir (rm, ref Rreaddir.Fail (status, a));

		Mreaddirplus =>
			status: int;
			(status, o) = g32(buf, o);
			a: ref Attr;
			(a, o) = gboolattr(buf, o);
			if(status == Eok) {
				rr := ref Rreaddirplus.Ok;
				rr.attr = a;
				(rr.cookieverf, o) = g64(buf, o);
				l: list of Entryplus;
				for(;;) {
					more: int;
					(more, o) = g32(buf, o);
					if(more == 0)
						break;
					e: Entryplus;
					(e.id, o) = g64(buf, o);
					(e.name, o) = gstr(buf, o, -1);
					(e.cookie, o) = g64(buf, o);
					(e.attr, o) = gboolattr(buf, o);
					b: int;
					(b, o) = g32(buf, o);
					if(b)
						(e.fh, o) = gfilehandle(buf, o);
					l = e::l;
				}
				dirs := array[len l] of Entryplus;
				i := len dirs-1;
				for(; l != nil; l = tl l)
					dirs[i--] = hd l;
				rr.dir = dirs;
				(rr.eof, o) = g32(buf, o);
				r = ref Rnfs.Readdirplus (rm, rr);
			} else
				r = ref Rnfs.Readdirplus (rm, ref Rreaddirplus.Fail (status, a));

		Mfsstat =>
			status: int;
			(status, o) = g32(buf, o);
			if(status == Eok) {
				rr := ref Rfsstat.Ok;
				(rr.attr, o) = gboolattr(buf, o);
				(rr.tbytes, o) = g64(buf, o);
				(rr.fbytes, o) = g64(buf, o);
				(rr.abytes, o) = g64(buf, o);
				(rr.tfiles, o) = g64(buf, o);
				(rr.ffiles, o) = g64(buf, o);
				(rr.afiles, o) = g64(buf, o);
				(rr.invarsec, o) = g32(buf, o);
				r = ref Rnfs.Fsstat (rm, rr);
			} else {
				rr := ref Rfsstat.Fail;
				rr.status = status;
				(rr.attr, o) = gboolattr(buf, o);
				r = ref Rnfs.Fsstat (rm, rr);
			}
		Mfsinfo =>
			status: int;
			(status, o) = g32(buf, o);
			if(status == Eok) {
				rr := ref Rfsinfo.Ok;
				(rr.attr, o) = gboolattr(buf, o);
				(rr.rtmax, o) = g32(buf, o);
				(rr.rtpref, o) = g32(buf, o);
				(rr.rtmult, o) = g32(buf, o);
				(rr.wtmax, o) = g32(buf, o);
				(rr.wtpref, o) = g32(buf, o);
				(rr.wtmult, o) = g32(buf, o);
				(rr.dtpref, o) = g32(buf, o);
				(rr.maxfilesize, o) = g64(buf, o);
				(rr.timedelta.secs, o) = g32(buf, o);
				(rr.timedelta.nsecs, o) = g32(buf, o);
				(rr.props, o) = g32(buf, o);
				r = ref Rnfs.Fsinfo (rm, rr);
			} else {
				rr := ref Rfsinfo.Fail;
				rr.status = status;
				(rr.attr, o) = gboolattr(buf, o);
				r = ref Rnfs.Fsinfo (rm, rr);
			}
		Mpathconf =>
			status: int;
			attr: ref Attr;
			(status, o) = g32(buf, o);
			(attr, o) = gboolattr(buf, o);
			if(status == Eok) {
				rr := ref Rpathconf.Ok;
				rr.attr = attr;
				(rr.linkmax, o) = g32(buf, o);
				(rr.namemax, o) = g32(buf, o);
				(rr.notrunc, o) = g32(buf, o);
				(rr.chownrestr, o) = g32(buf, o);
				(rr.caseinsens, o) = g32(buf, o);
				(rr.casepres, o) = g32(buf, o);
				r = ref Rnfs.Pathconf (rm, rr);
			} else {
				rr := ref Rpathconf.Fail (status, attr);
				r = ref Rnfs.Pathconf (rm, rr);
			}
		Mcommit =>
			status: int;
			(status, o) = g32(buf, o);
			wd: Weakdata;
			(wd, o) = gweakdata(buf, o);
			if(status == Eok) {
				rr := ref Rcommit.Ok (wd, big 0);
				(rr.writeverf, o) = g64(buf, o);
				r = ref Rnfs.Commit (rm, rr);
			} else {
				rr := ref Rcommit.Fail (status, wd);
				r = ref Rnfs.Commit (rm, rr);
			}
		* =>
			raise Badproc;
		}
		if(o != len buf)
			raise Badprocargs (sprint("%d leftover bytes, o %d, len buf %d", len buf-o, o, len buf));;
		return r;
	} exception e {
	Parse =>
		raise Badprocargs(e);
	Badproc =>
		raise;
	Badprocargs =>
		raise;
	}
}

rnfstagnames := array[] of {
"Null", "Getattr", "Setattr", "Lookup", "Access", "Readlink", "Read", "Write",
"Create", "Mkdir", "Symlink", "Mknod", "Remove", "Rmdir", "Rename", "Link",
"Readdir", "Readdirplus", "Fsstat", "Fsinfo", "Pathconf", "Commit",
};
Rnfs.text(mm: self ref Rnfs): string
{
	s := sprint("Rnfs.%s(", rnfstagnames[tagof mm]);
	pick m := mm {
	Null =>		;
	Getattr =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s", (ref r.attr).text());
		Fail =>	s += sprint("status %d", r.status);
		}
	Setattr =>
		s += sprint("status %d, weak %s", m.status, m.weak.text());
	Lookup =>
		pick r := m.r {
		Ok =>	s += sprint("fh %s, fhattr %s, dirattr %s", hex(r.fh), r.fhattr.text(), r.dirattr.text());
		Fail =>	s += sprint("status %d, dirattr %s", r.status, r.dirattr.text());
		}
	Access =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, access %#ux", r.attr.text(), r.access);
                Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
                }
	Readlink =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, path %q", r.attr.text(), r.path);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Read =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, count %d, eof %d, len data %d", r.attr.text(), r.count, r.eof, len r.data);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Write =>
		pick r := m.r {
		Ok =>	s += sprint("weak %s, count %d, stable %d, verf %bux", r.weak.text(), r.count, r.stable, r.verf);
		Fail =>	s += sprint("status %d, weak %s", r.status, r.weak.text());
		}
	Create or
	Mkdir or
	Symlink or
	Mknod =>
		pick r := m.r {
		Ok =>	s += sprint("fh %s, attr %s, weak %s", hex(r.fh), r.attr.text(), r.weak.text());
		Fail =>	s += sprint("status %d, weak %s", r.status, r.weak.text());
		}
	Remove or
	Rmdir =>
		s += sprint("status %d, weak %s", m.status, m.weak.text());
	Rename =>
		s += sprint("status %d, fromdir %s, todir %s", m.status, m.fromdir.text(), m.todir.text());
	Link =>
		s += sprint("status %d, attr %s, weak %s", m.status, m.attr.text(), m.weak.text());
	Readdir =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, cookieverf %bux, len dirs %d, eof %d", r.attr.text(), r.cookieverf, len r.dir, r.eof);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Readdirplus =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, cookieverf %bux, len dirs %d, eof %d", r.attr.text(), r.cookieverf, len r.dir, r.eof);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Fsstat =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, bytes t %bud, f %bud, a %bud, files t %bud, f %bud, a %bud, invarsec %d", r.attr.text(), r.tbytes, r.fbytes, r.abytes, r.tfiles, r.ffiles, r.afiles, r.invarsec);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Fsinfo =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, rtmax %d, rtpref %d, rtmult %d, wtmax %d, wtpref %d, wtmult %d, dtpref %d, maxfilesize %bud, timedelta %s, props %d", r.attr.text(), r.rtmax, r.rtpref, r.rtmult, r.wtmax, r.wtpref, r.wtmult, r.dtpref, r.maxfilesize, r.timedelta.text(), r.props);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Pathconf =>
		pick r := m.r {
		Ok =>	s += sprint("attr %s, linkmax %d, namemax %d, notrunc %d, chownrestr %d, caseinsens %d, casepres %d", r.attr.text(), r.linkmax, r.namemax, r.notrunc, r.chownrestr, r.caseinsens, r.casepres);
		Fail =>	s += sprint("status %d, attr %s", r.status, r.attr.text());
		}
	Commit =>
		pick r := m.r {
		Ok =>	s += sprint("weak %s, writeverf %bux", r.weak.text(), r.writeverf);
		Fail =>	s += sprint("status %d, weak %s", r.status, r.weak.text());
		}
	}
	s += ")";
	return s;
}

pboolattr(buf: array of byte, o: int, a: ref Attr): int
{
	o = pbool(buf, o, a != nil);
	if(a != nil)
		o = pattr(buf, o, *a);
	return o;
}

gboolattr(buf: array of byte, o: int): (ref Attr, int) raises (Parse)
{
	{
		b: int;
		attr: ref Attr;
		(b, o) = gbool(buf, o);
		if(b) {
			a: Attr;
			(a, o) = gattr(buf, o);
			attr = ref a;
		}
		return (nil, o);
	} exception e {
	Parse => raise Parse("gboolattr: "+e);
	}
}

gattr(buf: array of byte, o: int): (Attr, int) raises (Parse)
{
	{
		a: Attr;
		(a.ftype, o)	= g32(buf, o);
		(a.mode, o)	= g32(buf, o);
		(a.nlink, o)	= g32(buf, o);
		(a.uid, o)	= g32(buf, o);
		(a.gid, o)	= g32(buf, o);
		(a.size, o)	= g64(buf, o);
		(a.used, o)	= g64(buf, o);
		(a.rdev.major, o) = g32(buf, o);
		(a.rdev.minor, o) = g32(buf, o);
		(a.fsid, o)	= g64(buf, o);
		(a.fileid, o)	= g64(buf, o);
		(a.atime, o)	= g32(buf, o);
		(nil, o)	= g32(buf, o);
		(a.mtime, o)	= g32(buf, o);
		(nil, o)	= g32(buf, o);
		(a.ctime, o)	= g32(buf, o);
		(nil, o)	= g32(buf, o);
		return (a, o);
	} exception e {
	Parse => raise Parse("gsattr: "+e);
	}
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

gweakattr(buf: array of byte, o: int): (ref Weakattr, int) raises Parse
{
	{
		w := ref Weakattr;
		(w.size, o) = g64(buf, o);
		(w.mtime, o) = g32(buf, o);
		(nil, o) = g32(buf, o);
		(w.ctime, o) = g32(buf, o);
		(nil, o) = g32(buf, o);
		return (w, o);
	} exception e {
	Parse => raise Parse("gweakattr: "+e);
	}
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

gweakdata(buf: array of byte, o: int): (Weakdata, int) raises Parse
{
	{
		w: Weakdata;
		b: int;
		(b, o) = gbool(buf, o);
		if(b)
			(w.before, o) = gweakattr(buf, o);
		(w.after, o) = gboolattr(buf, o);
		return (w, o);
	} exception e {
	Parse => raise Parse("gweakdata: "+e);
	}
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
			raise Parse(sprint("bad value %#ux for sattr.setatime", a.setatime));
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
			raise Parse(sprint("bad value %#ux for sattr.setmtime", a.setmtime));
		}
		return (a, o);
	} exception e {
	Parse => raise Parse("gsattr: "+e);
	}
}

pboolval(buf: array of byte, o: int, b, v, zero: int): int
{
	o = p32(buf, o, b);
	if(b) {
		o = p32(buf, o, v);
		if(zero)
			o = p32(buf, o, 0);
	}
	return o;
}

psattr(buf: array of byte, o: int, a: Sattr): int
{
	o = pboolval(buf, o, a.setmode, a.mode, 0);
	o = pboolval(buf, o, a.setuid, a.uid, 0);
	o = pboolval(buf, o, a.setgid, a.gid, 0);
	o = p32(buf, o, a.setsize);
	if(a.setsize)
		o = p64(buf, o, a.size);
	o = pboolval(buf, o, a.setatime, a.atime, 1);
	o = pboolval(buf, o, a.setmtime, a.mtime, 1);
	return o;
}

gdirargs(buf: array of byte, o: int): (Dirargs, int) raises Parse
{
	{
		d: Dirargs;
		(d.fh, o) = gfilehandle(buf, o);
		(d.name, o) = gstr(buf, o, -1);
		return (d, o);
	} exception e {
	Parse => raise Parse("gdirargs: "+e);
	}
}

pdirargs(buf: array of byte, o: int, d: Dirargs): int
{
	o = popaque(buf, o, d.fh);
	o = pstr(buf, o, d.name);
	return o;
}


gcreatehow(buf: array of byte, o: int): (ref Createhow, int) raises Parse
{
	{
		createhow: int;
		cc: ref Createhow;
		(createhow, o) = g32(buf, o);
		case createhow {
		CreateUnchecked =>
			cc = c := ref Createhow.Unchecked;
			(c.attr, o) = gsattr(buf, o);
		CreateGuarded =>
			cc = c := ref Createhow.Guarded;
			(c.attr, o) = gsattr(buf, o);
		CreateExclusive =>
			cc = c := ref Createhow.Exclusive;
			(c.createverf, o) = g64(buf, o);
		* =>
			raise Parse(sprint("Tnfs.Create, bad createhow %d", createhow));
		}
		return (cc, o);
	} exception e {
	Parse => raise Parse("gcreatehow: "+e);
	}
}

pcreatehow(buf: array of byte, o: int, cc: ref Createhow): int
{
	pick c := cc {
	Unchecked =>
		o = p32(buf, o, CreateUnchecked);
		o = psattr(buf, o, c.attr);
	Guarded =>
		o = p32(buf, o, CreateGuarded);
		o = psattr(buf, o, c.attr);
	Exclusive =>
		o = p32(buf, o, CreateExclusive);
		o = p64(buf, o, c.createverf);
	* =>
		raise "missing case";
	}
	return o;
}

gnod(buf: array of byte, o: int): (ref Nod, int) raises Parse
{
	{
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
		* =>
			raise Parse("unrecognized nodetype");
		}
		return (nn, o);
	} exception e {
	Parse => raise Parse("gnod: "+e);
	}
}

pnod(buf: array of byte, o: int, nn: ref Nod): int
{
	pick n := nn {
	Chr =>
		o = p32(buf, o, FTchr);
		o = psattr(buf, o, n.attr);
		o = p32(buf, o, n.spec.major);
		o = p32(buf, o, n.spec.minor);
	Blk =>
		o = p32(buf, o, FTblk);
		o = psattr(buf, o, n.attr);
		o = p32(buf, o, n.spec.major);
		o = p32(buf, o, n.spec.minor);
	Sock =>
		o = p32(buf, o, FTsock);
		o = psattr(buf, o, n.attr);
	Fifo =>
		o = p32(buf, o, FTfifo);
		o = psattr(buf, o, n.attr);
	Reg =>	o = p32(buf, o, FTreg);
	Dir =>	o = p32(buf, o, FTdir);
	Lnk =>	o = p32(buf, o, FTlnk);
	* =>	raise "missing case";
	}
	return o;
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
