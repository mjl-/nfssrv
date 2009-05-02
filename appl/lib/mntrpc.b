implement Mntrpc;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "sunrpc.m";
	sunrpc: Sunrpc;
	g32, gopaque, gstr, p32, popaque, pstr: import sunrpc;
	Parse, Badprog, Badproc, Badprocargs, Badrpc: import sunrpc;
	Trpc, Rrpc, Auth: import sunrpc;
include "mntrpc.m";


init()
{
	sys = load Sys Sys->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
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
