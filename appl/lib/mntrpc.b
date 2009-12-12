implement Mntrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "util0.m";
	util: Util0;
	hex, l2a, rev: import util;
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, gstr, p32, popaque, pstr: import sunrpc;
	Parse, Badprog, Badproc, Badprocargs, Badrpc: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "mntrpc.m";

dflag = 0;

Filehandlesizemax: con 64;

mnttags = array[] of {
"null", "mnt", "dump", "umnt", "umntall", "export",
};

init()
{
	sys = load Sys Sys->PATH;
	util = load Util0 Util0->PATH;
	util->init();
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
}

error(status: int): string
{
	case status {
	Eok =>		return "success";
	Eperm =>	return "permission denied";
	Enoent =>	return "file does not exist";
	Eio =>		return "i/o error";
	Eaccess =>	return "permission denied";
	Enotdir =>	return "not a directory";
	Einval =>	return "bad arguments";
	Enametoolong =>	return "bad argument, name too long";
	Enotsupp =>	return "operation not supported";
	Eserverfault =>	return "server fault";
	* =>	return sprint("error %d", status);
	}
}

Tmnt.size(m: self ref Tmnt): int
{
	return m.pack(nil, 0);
}

Tmnt.pack(mm: self ref Tmnt, buf: array of byte, o: int): int
{
	o = mm.r.pack(buf, o);
	pick m := mm {
	Null =>		;
	Mnt =>		o = pstr(buf, o, m.dirpath);
	Dump =>		;
	Umnt =>		o = pstr(buf, o, m.dirpath);
	Umntall =>	;
	Export =>	;
	* =>	raise "missing case";
	}
	return o;
}

Tmnt.unpack(m: ref Trpc, buf: array of byte): ref Tmnt raises (Badrpc, Badprog, Badproc, Badprocargs)
{
	if(m.prog != ProgMnt)
		raise Badprog;
	if(m.vers != VersMnt) {
		nullverf: Auth; # will be fixed by caller
		raise Badrpc(sprint("bad version %d", m.vers), nil, ref Rrpc.Progmismatch (m.xid, nullverf, VersMnt, VersMnt));
	}

	{
		tt: ref Tmnt;
		o := 0;
		case m.proc {
		Mnull =>
			tt = ref Tmnt.Null (m);
		Mmnt =>
			dirpath: string;
			(dirpath, o) = gstr(buf, o, Mntpathmax);
			tt = ref Tmnt.Mnt (m, dirpath);
		Mdump =>
			tt = ref Tmnt.Dump (m);
		Mumnt =>
			dirpath: string;
			(dirpath, o) = gstr(buf, o, Mntpathmax);
			tt = ref Tmnt.Umnt (m, dirpath);
		Mumntall =>
			tt = ref Tmnt.Umntall (m);
		Mexport =>
			tt = ref Tmnt.Export (m);
		* =>
			raise Badproc;
		}
		if(o != len buf)
			raise Badprocargs(sprint("leftover bytes, o %d != len buf %d", o, len buf));
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

tmntnames := array[] of {"Null", "Mnt", "Dump", "Umnt", "Umntall", "Export"};
Tmnt.text(mm: self ref Tmnt): string
{
	s := sprint("Tmnt.%s(", tmntnames[tagof mm]);
	pick m := mm {
	Null =>		;
	Mnt =>		s += sprint("dirpath %q", m.dirpath);
	Dump =>		;
	Umnt =>		s += sprint("dirpath %q", m.dirpath);
	Umntall =>	;
	Export =>	;
	* =>
		raise "missing case";
	}
	s += ")";
	return s;
}

Rmnt.size(mm: self ref Rmnt): int
{
	return mm.pack(nil, 0);
}

Rmnt.pack(mm: self ref Rmnt, buf: array of byte, o: int): int
{
	o = mm.r.pack(buf, o);
	pick m := mm {
	Null =>
		;
	Mnt =>
		o = p32(buf, o, m.status);
		if(m.status == Eok) {
			o = popaque(buf, o, m.fh);
			o = p32(buf, o, len m.auths);
			for(i := 0; i < len m.auths; i++)
				o = p32(buf, o, m.auths[i]);
		}
	Dump =>
		for(i := 0; i < len m.mountlist; i++) {
			o = p32(buf, o, 1);
			o = pstr(buf, o, m.mountlist[i].t0);
			o = pstr(buf, o, m.mountlist[i].t1);
		}
		o = p32(buf, o, 0);
	Umnt =>
		;
	Umntall =>
		;
	Export =>
		for(i := 0; i < len m.exports; i++) {
			o = p32(buf, o, 1);
			e := m.exports[i];
			o = pstr(buf, o, e.dir);
			for(j := 0; j < len e.groups; j++) {
				o = p32(buf, o, 1);
				pstr(buf, o, e.groups[j]);
			}
			o = p32(buf, o, 0);
		}
		o = p32(buf, o, 0);
	* =>	raise "internal error";
	}
	return o;
}

Rmnt.unpack(tm: ref Trpc, rm: ref Rrpc, buf: array of byte): ref Rmnt raises (Badrpc, Badproc, Badprocargs)
{
	{
		r: ref Rmnt;
		o := 0;
		case tm.proc {
		Mnull =>
			r = ref Rmnt.Null (rm);
		Mmnt =>
			status: int;
			(status, o) = g32(buf, o);
			fh: array of byte;
			auths: array of int;
			if(status == Eok) {
				nauths: int;
				(fh, o) = gopaque(buf, o, Filehandlesizemax);
				(nauths, o) = g32(buf, o);
				if(nauths > 128) # don't know what the limit is...
					raise Badprocargs(sprint("Mnt response nauths %d too big", nauths));
				auths = array[nauths] of int;
				for(i := 0; i < nauths; i++)
					(auths[i], o) = g32(buf, o);
			}
			r = ref Rmnt.Mnt (rm, status, fh, auths);
		Mdump =>
			l: list of (string, string);
			for(;;) {
				more: int;
				(more, o) = g32(buf, o);
				if(more == 0)
					break;
				hostname, dir: string;
				(hostname, o) = gstr(buf, o, Mntnamemax);
				(dir, o) = gstr(buf, o, Mntpathmax);
				l = (hostname, dir):: l;
			}
			mntlist := array[len l] of (string, string);
			i := len l-1;
			for(; l != nil; l = tl l)
				mntlist[i--] = hd l;
			r = ref Rmnt.Dump (rm, mntlist);
		Mumnt =>
			r = ref Rmnt.Umnt (rm);
		Mumntall =>
			r = ref Rmnt.Umntall (rm);
		Mexport =>
			el: list of Export;
			for(;;) {
				more: int;
				(more, o) = g32(buf, o);
				if(more == 0)
					break;
				dir: string;
				(dir, o) = gstr(buf, o, Mntpathmax);
				gl: list of string;
				for(;;) {
					(more, o) = g32(buf, o);
					if(more == 0)
						break;
					group: string;
					(group, o) = gstr(buf, o, Mntnamemax);
					gl = group::gl;
				}
				groups := l2a(rev(gl));
				el = Export(dir, groups)::el;
			}
			exports := array[len el] of Export;
			i := len exports-1;
			for(; el != nil; el = tl el)
				exports[i--] = hd el;
			r = ref Rmnt.Export (rm, exports);
		* =>
			raise Badproc;
		}
		if(o != len buf)
			raise Badprocargs(sprint("leftover bytes, o %d != len buf %d", o, len buf));
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

rmntnames := array[] of {"Null", "Mnt", "Dump", "Umnt", "Umntall", "Export"};
Rmnt.text(mm: self ref Rmnt): string
{
	s := sprint("Rmnt.%s(", rmntnames[tagof mm]);
	pick m := mm {
	Null =>		;
	Mnt =>	
		s += sprint("status %d", m.status);
		if(m.status == Eok)
			s += sprint(", fh %s, len auths %d", hex(m.fh), len m.auths);
	Dump =>
		l := "";
		for(i := 0; i < len m.mountlist; i++)
			l += sprint(", %q %q", m.mountlist[i].t0, m.mountlist[i].t1);
		if(l != nil)
			l = l[1:];
		s += sprint("mountlist%s", l);
	Umnt =>		;
	Umntall =>	;
	Export =>
		l := "";
		for(i := 0; i < len m.exports; i++)
			l += sprint(", dir %q, len groups %d", m.exports[i].dir, len m.exports[i].groups);
		if(l != nil)
			l = l[1:];
		s += sprint("exports%s", l);
	* =>
		raise "missing case";
	}
	s += ")";
	return s;
}
