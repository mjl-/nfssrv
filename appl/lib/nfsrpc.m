Nfsrpc: module
{
	PATH:	con "/dis/lib/nfsrpc.dis";

	init:	fn();
	dflag:	int;

	ProgNfs: con 100003;
	VersNfs: con 3;

	Eok:		con 0;
	Eperm:	con 1;
	Enoent:	con 2;
	Eio:		con 5;
	Enxio:	con 6;
	Eacces:	con 13;
	Eexist:	con 17;
	Exdev:	con 18;
	Enodev:	con 19;
	Enotdir:	con 20;
	Eisdir:	con 21;
	Einval:	con 22;
	Efbig:	con 27;
	Enospc:	con 28;
	Erofs:	con 30;
	Emlink:	con 31;
	Enametoolong:	con 63;
	Enotempty:	con 66;
	Edquot:	con 69;
	Estale:	con 70;
	Eremote:	con 71;
	Ebadhandle:	con 10001;
	Enotsync:	con 10002;
	Ebadcookie:	con 10003;
	Enotsupp:	con 10004;
	Etoosmall:	con 10005;
	Eserverfault:	con 10006;
	Ebadtype:	con 10007;
	Ejukebox:	con 10008;

	error:	fn(v: int): string;
	pboolattr:	fn(buf: array of byte, o: int, a: ref Attr): int;

	# file types
	FTreg, FTdir, FTblk, FTchr, FTlnk, FTsock, FTfifo: con 1+iota;

	# access bits
	ACread, AClookup, ACmodify, ACextend, ACdelete, ACexecute: con 1<<iota;
	ACmask:	con ACread|AClookup|ACmodify|ACextend|ACdelete|ACexecute;

	# fsinfo bits
	FSFlink, FSFsymlink, FSFhomogeneous, FSFcansettime: con 1<<iota;
	FSFmask:	con FSFlink|FSFsymlink|FSFhomogeneous|FSFcansettime;

	Verfsize: con 8;
	Filehandlesizemax:	con 64;

	# device file
	Specdata: adt {
		minor, major:	int;
	};

	Time: adt {
		secs,
		nsecs:	int;

		text:	fn(t: self Time): string;
	};

	Attr: adt {
		ftype,
		mode,
		nlink,
		uid,
		gid:	int;
		size,
		used:	big;
		rdev:	Specdata;
		fsid:	big;
		fileid:	big;
		atime,
		mtime,
		ctime:	int;

		text:	fn(w: self ref Attr): string;
	};

	Weakattr: adt {
		size:	big;
		mtime,
		ctime:	int;

		text:	fn(w: self ref Weakattr): string;
	};

	Weakdata: adt {
		before:	ref Weakattr;	# nil iff false
		after:	ref Attr;	# nil iff false

		text:	fn(w: self Weakdata): string;
	};

	SETdontchange, SETtoservertime, SETtoclienttime: con iota; # setatime, setmtime
	Sattr: adt {
		setmode,
		mode,
		setuid,
		uid,
		setgid,
		gid:	int;
		setsize:	int;
		size:	big;
		setatime,
		atime,
		setmtime,
		mtime:	int;

		text:	fn(s: self Sattr): string;
	};
	nullsattr: con Sattr (0, 0, 0, 0, 0, 0, 0, big 0, 0, 0, 0, 0);

	Dirargs: adt {
		fh:	array of byte;
		name:	string;

		text:	fn(d: self Dirargs): string;
	};

	Nod: adt {
		pick {
		Chr or
		Blk =>
			attr:	Sattr;
			spec:	Specdata;
		Sock or
		Fifo =>
			attr:	Sattr;
		Reg or
		Dir or
		Lnk =>
		}

		text:	fn(n: self ref Nod): string;
	};

	Createhow: adt {
		pick {
		Unchecked or
		Guarded =>
			attr:	Sattr;
		Exclusive =>
			createverf:	big;
		}

		text:	fn(n: self ref Createhow): string;
	};

	WriteUnstable, WriteDatasync, WriteFilesync: con iota;
	CreateUnchecked, CreateGuarded, CreateExclusive: con iota;
	Tnfs: adt {
		r: ref Trpc;
		pick {
		Null =>
		Getattr =>
			fh:	array of byte;
		Setattr =>
			fh:	array of byte;
			newattr:	Sattr;
			haveguard:	int;
			guardctime:	int;  # if haveguard
		Lookup =>
			where:	Dirargs;
		Access =>
			fh:	array of byte;
			access:	int;
		Readlink =>
			fh:	array of byte;
		Read =>
			fh:	array of byte;
			offset:	big;
			count:	int;
		Write =>
			fh:	array of byte;
			offset:	big;
			count:	int;
			stablehow:	int;
			data:	array of byte;
		Create =>
			where:	Dirargs;
			createhow:	ref Createhow;
		Mkdir =>
			where:	Dirargs;
			attr:	Sattr;
		Symlink =>
			where:	Dirargs;
			attr:	Sattr;
			path:	string;
		Mknod =>
			where:	Dirargs;
			node:	ref Nod;
		Remove =>
			where:	Dirargs;
		Rmdir =>
			where:	Dirargs;
		Rename =>
			owhere,
			nwhere:	Dirargs;
		Link =>
			fh:	array of byte;
			link:	Dirargs;
		Readdir =>
			fh:	array of byte;
			cookie:	big;
			cookieverf:	big;
			count:	int;
		Readdirplus =>
			fh:	array of byte;
			cookie:	big;
			cookieverf:	big;
			dircount:	int;
			maxcount:	int;
		Fsstat =>
			rootfh:	array of byte;
		Fsinfo =>
			rootfh:	array of byte;
		Pathconf =>
			fh:	array of byte;
		Commit =>
			fh:	array of byte;
			offset:	big;
			count:	int;
		}

		size:	fn(m: self ref Tnfs): int;
		pack:	fn(m: self ref Tnfs, buf: array of byte, o: int): int;
		unpack:	fn(m: ref Trpc, buf: array of byte): ref Tnfs raises (Badrpc, Badprog, Badproc, Badprocargs);
		text:	fn(m: self ref Tnfs): string;
	};

	Rgetattr: adt {
		pick {
		Ok =>
			attr:	Attr;
		Fail =>
			status:	int;
		}
	};
	Rlookup: adt {
		pick {
		Ok =>
			fh:	array of byte;
			fhattr:		ref Attr; # may be nil
			dirattr:	ref Attr; # may be nil
		Fail =>
			status:	int;
			dirattr:	ref Attr; # may be nil
		}
	};
	Raccess: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			access:	int;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rreadlink: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			path:	string;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rread: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			count:	int;
			eof:	int;
			data:	array of byte;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rwrite: adt {
		pick {
		Ok =>
			weak:	Weakdata;
			count:	int;
			stable:	int;
			verf:	big;
		Fail =>
			status:	int;
			weak:	Weakdata;
		}
	};
	Rchange: adt {
		pick {
		Ok =>
			fh:	array of byte; # may be nil!
			attr:	ref Attr; # may be nil
			weak:	Weakdata;
		Fail =>
			status:	int;
			weak:	Weakdata;
		}
	};

	Entry: adt {
		id:	big;
		name:	string;
		cookie:	big;

		text:	fn(e: self Entry): string;
	};
	Entryplus: adt {
		id:	big;
		name:	string;
		cookie:	big;
		attr:	ref Attr; # may be nil
		fh:	array of byte; # may be nil

		text:	fn(e: self Entryplus): string;
	};
	Rreaddir: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			cookieverf:	big;
			dir:	array of Entry;
			eof:	int;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rreaddirplus: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			cookieverf:	big;
			dir:	array of Entryplus;
			eof:	int;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rfsstat: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			tbytes,
			fbytes,
			abytes,
			tfiles,
			ffiles,
			afiles:	big;
			invarsec:	int;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rfsinfo: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			rtmax,
			rtpref,
			rtmult,
			wtmax,
			wtpref,
			wtmult,
			dtpref:	int;
			maxfilesize:	big;
			timedelta:	Time;
			props:	int;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rpathconf: adt {
		pick {
		Ok =>
			attr:	ref Attr; # may be nil
			linkmax,
			namemax:	int;
			notrunc,
			chownrestr,	
			caseinsens,
			casepres:	int;
		Fail =>
			status:	int;
			attr:	ref Attr; # may be nil
		}
	};
	Rcommit: adt {
		pick {
		Ok =>
			weak:	Weakdata;
			writeverf:	big;
		Fail =>
			status:	int;
			weak:	Weakdata;
		}
	};

	Rnfs: adt {
		m: ref Rrpc;
		pick {
		Null =>
		Getattr =>
			r: ref Rgetattr;
		Setattr =>
			status:	int;
			weak:	Weakdata;
		Lookup =>
			r: ref Rlookup;
		Access =>
			r: ref Raccess;
		Readlink =>
			r: ref Rreadlink;
		Read =>
			r: ref Rread;
		Write =>
			r: ref Rwrite;
		Create or
		Mkdir or
		Symlink or
		Mknod =>
			r: ref Rchange;
		Remove or
		Rmdir =>
			status:	int;
			weak:	Weakdata;
		Rename =>
			status:	int;
			fromdir,
			todir:	Weakdata;
		Link =>
			status:	int;
			attr:	ref Attr; # may be nil
			weak:	Weakdata;
		Readdir =>
			r: ref Rreaddir;
		Readdirplus =>
			r: ref Rreaddirplus;
		Fsstat =>
			r: ref Rfsstat;
		Fsinfo =>
			r: ref Rfsinfo;
		Pathconf =>
			r: ref Rpathconf;
		Commit =>
			r: ref Rcommit;
		}

		size:	fn(m: self ref Rnfs): int;
		pack:	fn(m: self ref Rnfs, buf: array of byte, o: int): int;
		unpack:	fn(tm: ref Sunrpc->Trpc, rm: ref Sunrpc->Rrpc, buf: array of byte): ref Rnfs raises (Badrpc, Badproc, Badprocargs);
		text:	fn(m: self ref Rnfs): string;
	};
};
