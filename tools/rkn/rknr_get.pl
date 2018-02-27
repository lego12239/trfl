#!/usr/bin/perl -I. -W

use strict;
use rknr_xmlp;
use rknr_req;
use Getopt::Long qw(:config gnu_getopt);
use Sys::Syslog qw(:standard :macros);
use Text::CSV;
use URI;
use URI::_idna;
use Cwd;
use Data::Dumper;


my $conf = {
	SOAP_URI => undef,
	SOAP_NS => undef,
	TMPDIR => undef,
	BACKUPDIR => undef,
	VARDIR => undef,
	MAX_DOWNLOAD_INTERVAL => undef,
	SYSLOG_FACILITY => undef};
# conf optional parameters:
#   DOCVERSION_ONCHANGE
#   FORMATVERSION_ONCHANGE
#   APIVERSION_ONCHANGE
#
my $time_last;
my $ret;
my $entry;
my $xmlp;
my $csv;
my $db = {};
my $files;
my $tf_list_path;
my ($fh_uris, $fh_domains, $fh_tf);
my ($opt_req, $opt_sig, $opt_in, $opt_out);


sub report_err
{
	my ($msg) = @_;


	print(STDERR "error: ".$msg."\n");
	syslog(LOG_ERR, "error: ".$msg);
}

sub conf_set
{
	my ($name, $val) = @_;
	
	$conf->{uc($name)} = $val;
}

sub conf_check
{
	my @prms;
	my $prm;
	
	@prms = keys(%$conf);
	foreach $prm (@prms) {
		if (!defined($conf->{$prm})) {
			die("conf parameter ".$prm." is not supplied");
		}
	}
}

sub conf_load
{
	my ($fname) = @_;
	my @prms;
	my $prm;
	my $fh;
	my $line;
	
	unless (open($fh, "<", $fname)) {
		die("can't open conf file: ".$!);
	}
	while (defined($line = <$fh>)) {
		chomp($line);
		next if ($line =~ /^\s*\#/o);
		next if ($line =~ /^\s*$/o);
		unless ($line =~ s/^\s*(\S+)\s*=\s*//o) {
			die("conf format error in line: ".$line);
		}
		$prm = $1;
		$line =~ s/^\"//o;
		$line =~ s/\"\s*$//o;
		conf_set($prm, $line);
	}
	close($fh);
	conf_check();
}

sub bin_run
{
	my ($fname) = @_;
	my $err;
	
	return if (!defined($fname));
	
	$err = `$fname 2>&1`;
	if ($? == -1) {
		die("failed to execute $fname: $!: $err");
	} elsif ($? & 127) {
		die("child($fname) died with signal ".($? & 127).": $err");
	} elsif (($? >> 8) != 0) {
		die("child($fname) exited with value ".($? >> 8).": $err");
	}
}

sub db_add
{
	my ($type) = @_;
	my $rec;
	my $i;
	
	if (!$csv->combine(@_)) {
		syslog(LOG_ERR, "can't combine csv rec: %s: %s",
		  $csv->error_input(), $csv->error_diag());
		return -1;
	}
	$rec = $csv->string();
	if (defined($db->{$type})) {
		foreach $i (@{$db->{$type}}) {
			return 0 if ($i eq $rec);
		}
	}
	push(@{$db->{$type}}, $rec);
	
	return 0;
}

sub parse_uri
{
	my ($uri) = @_;
	my $tmp;
	my $p = {};
	
	$uri =~ s/^([^:]+)://o;
	$p->{scheme} = $1;
	# Is authority exist?
	if ($uri =~ s/^\/\///o) {
		$p->{authority} = {};
		$tmp->{end} = length($uri);
		$tmp->{pos} = index($uri, "/");
		if (($tmp->{pos} != -1) && ($tmp->{pos} < $tmp->{end})) {
			$tmp->{end} = $tmp->{pos};
		}
		$tmp->{pos} = index($uri, "?");
		if (($tmp->{pos} != -1) && ($tmp->{pos} < $tmp->{end})) {
			$tmp->{end} = $tmp->{pos};
		}
		$tmp->{pos} = index($uri, "#");
		if (($tmp->{pos} != -1) && ($tmp->{pos} < $tmp->{end})) {
			$tmp->{end} = $tmp->{pos};
		}
		$p->{authority}{_full} = substr($uri, 0, $tmp->{end});
		$uri = substr($uri, $tmp->{end});
		
		$tmp->{str} = $p->{authority}{_full};
		if ($tmp->{str} =~ s/^([^\@]+)\@//o) {
			$p->{authority}{userinfo} = $1;
		}
		
		if ($tmp->{str} =~ s/:(\d+)$//o) {
			$p->{authority}{port} = $1;
		}

		$p->{authority}{host} = $tmp->{str};
	}
	# Is path exist?
	return $p if ($uri eq "");
	$tmp->{end} = length($uri);
	$tmp->{q} = index($uri, '?');
	if (($tmp->{q} != -1) && ($tmp->{q} < $tmp->{end})) {
		$tmp->{end} = $tmp->{q};
	}
	$tmp->{f} = index($uri, '#');
	if (($tmp->{f} != -1) && ($tmp->{f} < $tmp->{end})) {
		$tmp->{end} = $tmp->{f};
	}
	$p->{path} = substr($uri, 0, $tmp->{end});
	$p->{path} = undef if ($p->{path} eq "");
	$uri = substr($uri, $tmp->{end});
	
	# Is query exist?
	return $p if ($uri eq "");
	$tmp->{q} -= $tmp->{end};
	$tmp->{f} -= $tmp->{end};
	if ($tmp->{q} >= 0) {
		if ($tmp->{f} >= 0) {
			if ($tmp->{q} < $tmp->{f}) {
				$p->{query} = substr($uri, $tmp->{q} + 1, $tmp->{f} - 1);
				$uri = substr($uri, $tmp->{f});
			}
		} else {
			$p->{query} = substr($uri, $tmp->{q} + 1);
			$uri = "";
		}
	}
	return $p if ($uri eq "");
	$p->{fragment} = substr($uri, 1);
	
	return $p;
}

sub fmt_uri
{
	my ($uri) = @_;
	my $str = "";
	
	$str .= $uri->{scheme}.":";
	if (defined($uri->{authority})) {
		$str .= "//";
		if (defined($uri->{authority}{userinfo})) {
			$str .= $uri->{authority}{userinfo}.'@';
		}
		$str .= $uri->{authority}{host};
		if (defined($uri->{authority}{port})) {
			$str .= ":".$uri->{authority}{port};
		}
	}
	if (defined($uri->{path})) {
		$str .= $uri->{path};
	}
	if (defined($uri->{query})) {
		$str .= "?".$uri->{query};
	}
	if (defined($uri->{fragment})) {
		$str .= '#'.$uri->{fragment};
	}
	
	return $str;
}

sub output_help
{
	print("Usage: rknr_get.pl OPTIONS CONF_FILE\n\n".
	  "Options:\n".
	  " -i, --input=FILE     input xml file(do not load it from RKN site)\n".
	  " -o, --output=FILE     output file\n".
	  " -r, --request=FILE	  request file\n".
	  " -s, --signature=FILE  signature file\n".
	  " -v, --version         show program version\n");
}

sub output_version
{
	print("rknr_get.pl 0-2.4\n");
}

sub proc_opts
{
	my ($opt_h, $opt_v);


	GetOptions('request|req|r=s' => \$opt_req,
	  'input|i=s' => \$opt_in,
	  'output|o=s' => \$opt_out,
	  'signature|sig|s=s' => \$opt_sig,
	  'help|h' => \$opt_h,
	  'version|v' => \$opt_v);

	if ( $opt_h ) {
		output_help();
		exit(0);
	}
	
	if ($opt_v) {
		output_version();
		exit(0);
	}
}

sub get_file_from_zip
{
	my ($data, $file) = @_;
	my $fh;
	my @xmls;

	unless (mkdir($conf->{TMPDIR})) {
		if ($! != 17) {
			die("Can't create a temp directory: ".$!);
		}
	}
	unless (open($fh, ">", $file)) {
		die("Cann't create a zip file '$file': $!");
	}
	print($fh $data);
	close($fh);

	system("unzip -o $file '*.xml' -d ".$conf->{TMPDIR});

	@xmls = glob($conf->{TMPDIR}."/*.xml"); 
	return \@xmls;
}

sub prework
{
	$tf_list_path = $opt_out.".".$$;
	unless (open($fh_tf, ">", $tf_list_path)) {
		report_err("Can't open file ".$tf_list_path);
		exit(1);
	}
	$csv = Text::CSV->new({binary => 1, sep_char => ":", quote_char => "'",
	  escape_char => "'"});
	if (!$csv) {
		report_err("Can't create csv instance");
		exit(1);
	}
}

sub postwork
{
	my @types;
	my $type;
	my $i;
	my $lineno = 0;
	my $postfix;
	
	@types = keys(%$db);
	foreach $type (@types) {
		foreach $i (@{$db->{$type}}) {
			$lineno++;
			#print(stderr "line $lineno\n");
			print($fh_tf $i."\n");
		}
	}
	close($fh_tf);
	@types = localtime(time());
	$postfix = sprintf(".%04d-%02d-%02dT%02d:%02d", 
	  $types[5] + 1900, $types[4] + 1, $types[3], $types[2], $types[1]);
	$type = $conf->{BACKUPDIR}."/tf_list".$postfix;
	unless (rename($tf_list_path, $type)) {
		die("Can't rename tf_list temp file to ".$type.": ".$!);
	}
	unless (unlink($opt_out)) {
		if ($! != 2) {
			die("Can't remove tf_list symlink: ".$!);
		}
	}
	unless (symlink(getcwd()."/".$type, $opt_out)) {
		die("Can't create tf_list symlink: ".$!);
	}
	@types = glob($conf->{TMPDIR}."/*.xml");
	$i = 0;
	foreach $type (@types) {
		unless (rename($type, $conf->{BACKUPDIR}."/dump$i".$postfix)) {
			die("Can't rename dump xml file to ".
			  $conf->{BACKUPDIR}."/dump$i".$postfix.": ".$!);
		}
		$i++;
	}
	
	if (defined($time_last)) {
		set_var_uint("time_last", $time_last);
	}
}

sub block_entry
{
	my ($entry) = @_;
	
	if (!defined($entry->{__ATTRS}{blockType})) {
		$entry->{__ATTRS}{blockType} = "default";
	}
	if ($entry->{__ATTRS}{blockType} eq "default") {
		if (defined($entry->{url})) {
			block_entry_by_uris($entry);
		} elsif (defined($entry->{domain})) {
			block_entry_by_domains($entry);
		} else {
			if (defined($entry->{ip})) {
				block_entry_by_ips($entry);
			}
			if (defined($entry->{ipSubnet})) {
				block_entry_by_ipprefs($entry);
			}
			if ((!defined($entry->{ip})) && (!defined($entry->{ipSubnet}))) {
				syslog(LOG_ERR, "entry without uri, domain and ip: %s",
				  Dumper($entry));
				return 1;
			}
		}
	} elsif ($entry->{__ATTRS}{blockType} eq "domain") {
		block_entry_by_domains($entry);
	} elsif ($entry->{__ATTRS}{blockType} eq "domain-mask") {
		block_entry_by_domainmasks($entry);
	} elsif ($entry->{__ATTRS}{blockType} eq "ip") {
		if (defined($entry->{ip})) {
			block_entry_by_ips($entry);
		}
		if (defined($entry->{ipSubnet})) {
			block_entry_by_ipprefs($entry);
		}
		if ((!defined($entry->{ip})) && (!defined($entry->{ipSubnet}))) {
			syslog(LOG_ERR, "blockType is %s but no ip or ipSubnet entry ".
			  "is found: %s", $entry->{__ATTRS}{blockType}, Dumper($entry));
		}
	} else {
		syslog(LOG_ERR, "unknown blockType: %s: %s",
		  $entry->{__ATTRS}{blockType}, Dumper($entry));
		return 1;
	}
	
	return 1;
}

sub block_entry_by_uris
{
	my ($entry) = @_;
	my $i;
	
	foreach $i (@{$entry->{url}}) {
		if (block_entry_by_uri($i->{__TEXT}) == 1) {
			block_entry_by_ips($entry);
		}
	}
	
	return 0;
}

sub block_entry_by_uri
{
	my ($uri) = @_;
	my $uri_parsed;
	my @p;
	my $str;
	my $ret;
	
	$uri_parsed = parse_uri($uri);
	if ($uri_parsed->{scheme} eq "http") {
		$uri_parsed = URI->new($uri);
		$uri_parsed->fragment(undef);
		$uri_parsed->userinfo(undef);
		$uri_parsed->host(lc($uri_parsed->host()));
		$str = $uri_parsed->path();
		$str =~ s/\/+/\//go;
		$str =~ s/\/$//o;
		$uri_parsed->path($str);
		return db_add("uri", $uri_parsed->as_string());
	} elsif ($uri_parsed->{scheme} eq "https") {
		$uri_parsed = URI->new($uri);
		$uri_parsed->scheme("http");
		$uri_parsed->fragment(undef);
		$uri_parsed->userinfo(undef);
		$uri_parsed->host(lc($uri_parsed->host()));
		$str = $uri_parsed->path();
		$str =~ s/\/+/\//go;
		$str =~ s/\/$//o;
		$uri_parsed->path($str);
		$ret = db_add("uri", $uri_parsed->as_string());
		return $ret if ($ret < 0);
		return db_add("domain", $uri_parsed->host());
	} elsif ($uri_parsed->{scheme} eq "newcamd525") {
		if (!defined($uri_parsed->{authority}{port})) {
			syslog(LOG_ERR, "can't get port for uri: %s", $uri);
			return -1;
		}
		return 1;
	} else {
		syslog(LOG_ERR, "unknown uri scheme: %s", $uri);
		return -1;
	}
	
	return 0;
}

sub block_entry_by_domains
{
	my ($entry) = @_;
	my $i;
	my $ret;
	
	foreach $i (@{$entry->{domain}}) {
		$ret = db_add("domain", URI::_idna::encode(lc($i->{__TEXT})));
		return $ret if ($ret < 0);
	}
	
	return 0;
}

sub block_entry_by_domainmasks
{
	my ($entry) = @_;
	my $i;
	my $str;
	my $ret;
	
	foreach $i (@{$entry->{domain}}) {
		$str = $i->{__TEXT};
		if (substr($str, 0, 2) ne '*.') {
			syslog(LOG_ERR, "domain-mask entry not started with '*.': %s",
			  $i->{__TEXT});
			return -1;
		}
		$str = substr($str, 2);
		$ret = db_add("domain-tree", URI::_idna::encode(lc($str)));
		return $ret if ($ret < 0);
	}
	
	return 0;
}

sub block_entry_by_ips
{
	my ($entry) = @_;
	my $i;
	my $ret;
	
	foreach $i (@{$entry->{ip}}) {
		$ret = db_add("ip-srv", $i->{__TEXT});
		return $ret if ($ret < 0);
	}
	
	return 0;
}

sub block_entry_by_ipprefs
{
	my ($entry) = @_;
	my $i;
	my $ret;
	
	foreach $i (@{$entry->{ipSubnet}}) {
		$ret = db_add("ip-srv", $i->{__TEXT});
		return $ret if ($ret < 0);
	}
	
	return 0;
}

sub get_var_any
{
	my ($name) = @_;
	my $fh;
	my $ret;
	
	unless (open($fh, "<", $conf->{VARDIR}."/$name")) {
		if ($! == 2) {
			return "";
		}
		die("can't open ".$conf->{VARDIR}."/$name: ".$!);
	}
	$ret = <$fh>;
	close($fh);

	return $ret;
}

sub set_var_any
{
	my ($name, $val) = @_;
	my $fh;
	
	unless (open($fh, ">", $conf->{VARDIR}."/$name")) {
		die("can't open ".$conf->{VARDIR}."/$name: ".$!);
	}
	print($fh $val);
	close($fh);
}

sub get_var_uint
{
	my ($name) = @_;
	my $fh;
	my $val;
	
	unless (open($fh, "<", $conf->{VARDIR}."/$name")) {
		if ($! == 2) {
			return 0;
		}
		die("can't open ".$conf->{VARDIR}."/$name: ".$!);
	}
	$val = <$fh>;
	close($fh);

	if ($val !~ /^[0-9]+$/o) {
		unlink($conf->{VARDIR}."/$name");
		$val = 0;
	}
	return $val;
}

sub set_var_uint
{
	my ($name, $val) = @_;
	my $fh;
	
	unless (open($fh, ">", $conf->{VARDIR}."/$name")) {
		die("can't open ".$conf->{VARDIR}."/$name: ".$!);
	}
	print($fh $val);
	close($fh);
}

sub handle_ver_docs
{
	my ($ver) = @_;
	my $ver_last;
	
	syslog(LOG_INFO, "DOCVERSION - ".$ver);
	eval {
		$ver_last = get_var_any("ver_docs");
		if ($ver_last != $ver) {
			syslog(LOG_INFO, "Fire callback");
			bin_run($conf->{DOCVERSION_ONCHANGE});
			set_var_any("ver_docs", $ver);
		}
	};
	if ($@) {
		syslog(LOG_WARNING, "Handling of docs version change error: ".$@);
	}
}

sub handle_ver_regfmt
{
	my ($ver) = @_;
	my $ver_last;
	
	syslog(LOG_INFO, "FORMATVERSION - ".$ver);
	eval {
		$ver_last = get_var_any("ver_regfmt");
		if ($ver_last != $ver) {
			syslog(LOG_INFO, "Fire callback");
			bin_run($conf->{FORMATVERSION_ONCHANGE});
			set_var_any("ver_regfmt", $ver);
		}
	};
	if ($@) {
		syslog(LOG_WARNING, "Handling of registry format version change ".
		  "error: ".$@);
	}
}

sub handle_ver_api
{
	my ($ver) = @_;
	my $ver_last;
	
	syslog(LOG_INFO, "APIVERSION - ".$ver);
	eval {
		$ver_last = get_var_any("ver_api");
		if ($ver_last != $ver) {
			syslog(LOG_INFO, "Fire callback");
			bin_run($conf->{APIVERSION_ONCHANGE});
			set_var_any("ver_api", $ver);
		}
	};
	if ($@) {
		syslog(LOG_WARNING, "Handling of api version change error: ".$@);
	}
}

sub get_registry
{
	my $req;
	my $arch;
	my $files;
	my $info;
	my $time = time() * 1000;
	
	$req = new rknr_req(soap_uri => $conf->{SOAP_URI},
	  soap_ns => $conf->{SOAP_NS}, req => $opt_req, sig => $opt_sig);
	$time_last = get_var_uint("time_last");
	$info = $req->get_info();
	handle_ver_docs($info->{ver_docs});
	handle_ver_regfmt($info->{ver_regfmt});
	handle_ver_api($info->{ver_api});
	
	syslog(LOG_INFO, "registry urgent update time is ".$info->{ut_urgent}.
	  "; loaded - ".$time_last);
	if (($info->{ut_urgent} <= $time_last) &&
	    (($time - $time_last) < $conf->{MAX_DOWNLOAD_INTERVAL})) {
		return;
	}
	$time_last = $info->{ut_urgent};
	if (($time - $time_last) >= $conf->{MAX_DOWNLOAD_INTERVAL}) {
		syslog(LOG_INFO, "MAX_DOWNLOAD_INTERVAL is reached");
		# Use 600 seconds to be safe of time differencies
		$time_last = $time - 600 * 1000;
	}
	syslog(LOG_INFO, "download the archive...");
	$arch = $req->get_data();
	syslog(LOG_INFO, "unpack the archive...");
	$files = get_file_from_zip($arch, $conf->{TMPDIR}."/data.zip");
	syslog(LOG_INFO, "archive is unpacked");
	
	return $files;
}

sub main
{
	my $dh;
	
	if (!defined($opt_in)) {
		if ((!defined($opt_req)) || ($opt_req eq "")) {
			die("A file error: a request file is not specified");
		}
		if ((!defined($opt_sig)) || ($opt_sig eq "")) {
			die("A file error: a signature file is not specified");
		}
		unless (open($dh, "<", $opt_req)) {
			die("A request file error: $!");
		}
		close($dh);
		unless (open($dh, "<", $opt_sig)) {
			die("A signature file error: $!");
		}
		close($dh);
	}
	if ((!defined($opt_out)) || ($opt_out eq "")) {
		die("A file error: an output file is not specified");
	}
	
	unless (mkdir($conf->{VARDIR})) {
		if ($! != 17) {
			die("Can't create a var directory: ".$!);
		}
	}
	unless (mkdir($conf->{BACKUPDIR})) {
		if ($! != 17) {
			die("Can't create a backup directory: ".$!);
		}
	}

	if ($opt_in) {
		$files = [ $opt_in ];
	} else {
		$files = get_registry();
		if (!defined($files)) {
			return;
		}
	}

	prework();
	
	syslog(LOG_INFO, "processing");
	foreach my $file (@$files) {
		$xmlp = new rknr_xmlp(file => $file,
		  cb => {"/reg:register/content" => \&block_entry});
		$xmlp->xml_parse();
	}
	
	postwork();
}


######################################################################
# MAIN
######################################################################

proc_opts();

eval {

	if ((!defined($ARGV[0])) || ($ARGV[0] eq "")) {
		die("configuration file must be specified!");
	}
	conf_load($ARGV[0]);

	openlog("[rknr_get.pl]", "", $conf->{SYSLOG_FACILITY});
	syslog(LOG_INFO, "started");

	main();
};
if ($@) {
	report_err($@);
	syslog(LOG_ERR, "FAIL (".$@.")");
	exit(1);
}
syslog(LOG_INFO, "SUCCESS");
closelog();
exit(0);
