implement Testmntrpc;

include "sys.m";
	sys: Sys;
	print, sprint: import sys;
include "draw.m";
include "arg.m";
include "sunrpc.m";
	sunrpc: Sunrpc;
	Parse, Badrpc, Badprog, Badproc, Badprocargs: import sunrpc;
include "../lib/mntrpc.m";
	mntrpc: Mntrpc;
	Tmnt, Rmnt: import mntrpc;
include "util0.m";
	util: Util0;
	l2a, a2l, join, warn, fail, hex, unhex: import util;

Testmntrpc: module {
	init:	fn(nil: ref Draw->Context, nil: list of string);
};


dflag: int;
tflag: int;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	sunrpc = load Sunrpc Sunrpc->PATH;
	sunrpc->init();
	mntrpc = load Mntrpc Mntrpc->PATH;
	mntrpc->init();
	util = load Util0 Util0->PATH;
	util->init();

	arg->init(args);
	arg->setusage(arg->progname()+" [-dt] host port [null | mnt path | dump | umnt path | umntall | export]");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		't' =>	tflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args < 3)
		arg->usage();
	host := hd args;
	port := int hd tl args;
	op := hd tl tl args;
	t := l2a(tl tl tl args);
	tr := ref Sunrpc->Trpc (sys->millisec(), Sunrpc->Rpcversion, Mntrpc->ProgMnt, Mntrpc->VersMnt, -1, Sunrpc->Auth(Sunrpc->Anone, nil), Sunrpc->Auth(Sunrpc->Anone, nil));
	tm: ref Tmnt;
	if(op == "mnt" || op == "umnt") {
		if(len t != 1)
			arg->usage();
	} else {
		if(len t != 0)
			arg->usage();
	}
	case op {
	"null" =>	tm = ref Tmnt.Null (tr);
	"mnt" =>	tm = ref Tmnt.Mnt (tr, t[0]);
	"dump" =>	tm = ref Tmnt.Dump (tr);
	"umnt" =>	tm = ref Tmnt.Umnt (tr, t[0]);
	"umntall" =>	tm = ref Tmnt.Umntall (tr);
	"export" =>	tm = ref Tmnt.Export (tr);
	* =>
		arg->usage();
	}
	tr.proc = tagof tm;

	addr := sprint("udp!%s!%d", host, port);
	if(tflag)
		addr = sprint("tcp!%s!%d", host, port);
	(ok, conn) := sys->dial(addr, nil);
	if(ok != 0)
		fail(sprint("dial: %r"));
	fd := conn.dfd;

	if(dflag)
		warn("-> "+mntrpc->mnttags[tagof tm]);
	err := sunrpc->writerpc(fd, nil, tflag, tm);
	if(err != nil)
		fail("writing rpc: "+err);
	buf: array of byte;
	if(tflag) {
		(buf, err) = sunrpc->readmsg(fd);
	} else {
		n := sys->read(fd, buf = array[64*1024] of byte, len buf);
		if(n < 0)
			err = sprint("read: %r");
		else
			buf = buf[:n];
	}
	if(err != nil)
		fail("reading rpc: "+err);
	{
		rm: ref Rmnt;
		rm = sunrpc->parseresp(tr, buf, rm);
		if(dflag)
			warn("<- "+mntrpc->mnttags[tagof rm]);
		if(rm.r.xid != tm.r.xid)
			fail(sprint("xid mismatch, sent %d, got %d", rm.r.xid, tm.r.xid));
		if(tagof rm != tagof tm)
			fail(sprint("proc mismatch, sent %d, got %d", tagof tm, tagof rm));
		
		pick m := rm {
		Null =>	;
		Mnt =>
			case m.status {
			Mntrpc->Eok =>
				print("status %d (ok)\n", m.status);
				print("filehandle %s\n", hex(m.fh));
				s := "";
				for(i := 0; i < len m.auths; i++)
					s += " "+string m.auths[i];
				if(s != nil)
					s = s[1:];
				print("auths:\n\t%s\n", s);
			Mntrpc->Eperm =>	print("status Eperm\n");
			Mntrpc->Enoent =>	print("status Enoent\n");
			Mntrpc->Eio =>		print("status Eio\n");
			Mntrpc->Eaccess =>	print("status Eaccess\n");
			Mntrpc->Enotdir =>	print("status Enotdir\n");
			Mntrpc->Einval =>	print("status Einval\n");
			Mntrpc->Enametoolong =>	print("status Enametoolong\n");
			Mntrpc->Enotsupp =>	print("status Enotsupp\n");
			Mntrpc->Eserverfault =>	print("status Eserverfault\n");
			* =>
				print("status %d (failure)\n", m.status);
			}
		Dump =>
			for(i := 0; i < len m.mountlist; i++)
				print("%s %s\n", m.mountlist[i].t0, m.mountlist[i].t1);
		Umnt =>
			;
		Umntall =>
			;
		Export =>
			for(i := 0; i < len m.exports; i++) {
				e := m.exports[i];
				print("dir %s\ngroups:\n\t%s\n", e.dir, join(a2l(e.groups), " "));
			}
		* =>
			raise "missing case";
		}
	} exception e {
	Badrpc =>	fail("response: "+e.t0);
	Badproc =>	fail("response: bad proc");
	Badprocargs =>	fail("response: bad procargs");
	}
}
