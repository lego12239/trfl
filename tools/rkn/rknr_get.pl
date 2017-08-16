#!/usr/bin/perl -I. -W

use strict;
use rknr_xmlp;
use rknr_req;
use Getopt::Long qw(:config gnu_getopt);
use Sys::Syslog qw(:standard :macros);
use Text::CSV;
use URI;
use Cwd;
use Data::Dumper;


use constant {
	SOAP_URI => "http://vigruzki.rkn.gov.ru/services/OperatorRequest/",
	SOAP_NS => "http://vigruzki.rkn.gov.ru/OperatorRequest/",
	TMPDIR => "tmp",
	BACKUPDIR => "backup",
	SYSLOG_FACILITY => LOG_LOCAL7,
};

my $req;
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
	print("Usage: rknr_get.pl OPTIONS\n\n".
	  "Options:\n".
	  " -i, --input=FILE     input xml file(do not load it from RKN site)\n".
	  " -o, --output=FILE     output file\n".
	  " -r, --request=FILE	  request file\n".
	  " -s, --signature=FILE  signature file\n".
	  " -v, --version         show program version\n");
}

sub output_version
{
	print("rknr_get.pl 0-1.0\n");
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

	unless (mkdir(TMPDIR)) {
		if ($! != 17) {
			die("Can't create a temp directory: ".$!);
		}
	}
	unless (open($fh, ">", $file)) {
		die("Cann't create a zip file '$file': $!");
	}
	print($fh $data);
	close($fh);

	system("unzip -o $file '*.xml' -d ".TMPDIR);

	@xmls = glob(TMPDIR."/*.xml"); 
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
	unless (mkdir(BACKUPDIR)) {
		if ($! != 17) {
			die("Can't create a backup directory: ".$!);
		}
	}
	@types = localtime(time());
	$postfix = sprintf(".%04d-%02d-%02dT%02d:%02d", 
	  $types[5] + 1900, $types[4] + 1, $types[3], $types[2], $types[1]);
	$type = BACKUPDIR."/tf_list".$postfix;
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
	@types = glob(TMPDIR."/*.xml");
	$i = 0;
	foreach $type (@types) {
		unless (rename($type, BACKUPDIR."/dump$i".$postfix)) {
			die("Can't rename dump xml file to ".
			  BACKUPDIR."/dump$i".$postfix.": ".$!);
		}
		$i++;
	}
}

sub block_entry
{
	my ($entry) = @_;
	
	if (!defined($entry->{__attrs}{blockType})) {
		$entry->{__attrs}{blockType} = "default";
	}
	if ($entry->{__attrs}{blockType} eq "default") {
		if (defined($entry->{url})) {
			block_entry_by_uris($entry);
		} elsif (defined($entry->{domain})) {
			block_entry_by_domains($entry);
		} elsif (defined($entry->{ip})) {
			block_entry_by_ips($entry);
		} elsif (defined($entry->{ipSubnet})) {
			block_entry_by_ipprefs($entry);
		} else {
			syslog(LOG_ERR, "entry without uri, domain and ip: %s",
			  Dumper($entry));
			return;
		}
	} elsif ($entry->{__attrs}{blockType} eq "domain") {
		block_entry_by_domains($entry);
	} elsif ($entry->{__attrs}{blockType} eq "domain-mask") {
		block_entry_by_domainmasks($entry);
	} elsif ($entry->{__attrs}{blockType} eq "ip") {
		if (defined($entry->{ip})) {
			block_entry_by_ips($entry);
		} elsif (defined($entry->{ipSubnet})) {
			block_entry_by_ipprefs($entry);
		} else {
			syslog(LOG_ERR, "blockType is %s but no ip or ipSubnet entry ".
			  "is found: %s", $entry->{__attrs}{blockType}, Dumper($entry));
		}
	} else {
		syslog(LOG_ERR, "unknown blockType: %s: %s",
		  $entry->{__attrs}{blockType}, Dumper($entry));
		return;
	}
}

sub block_entry_by_uris
{
	my ($entry) = @_;
	my $array;
	my $i;
	
	if (ref($entry->{url}) eq "ARRAY") {
		$array = $entry->{url};
	} elsif (ref($entry->{url}) eq "HASH") {
		$array = [$entry->{url}];
	} else {
		syslog(LOG_ERR, "url key unknown type: %s: %s",
		  ref($entry->{url}), Dumper($entry));
		return -1;
	}
	
	foreach $i (@$array) {
		if (block_entry_by_uri($i->{__text}) == 1) {
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
	my $i;
	my $ret;
	
	$uri_parsed = parse_uri($uri);
	if ($uri_parsed->{scheme} eq "http") {
		$uri_parsed = URI->new($uri);
		$uri_parsed->fragment(undef);
		$uri_parsed->host(lc($uri_parsed->host()));
		return db_add("uri", $uri_parsed->as_string());
	} elsif ($uri_parsed->{scheme} eq "https") {
		$uri_parsed = URI->new($uri);
		$uri_parsed->scheme("http");
		$uri_parsed->fragment(undef);
		$uri_parsed->host(lc($uri_parsed->host()));
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
		syslog(LOG_ERR, "unknown uri scheme: %s",
		  $entry->{url}{__text});
		return -1;
	}
	
	return 0;
}

sub block_entry_by_domains
{
	my ($entry) = @_;
	my $array;
	my $i;
	my $ret;
	
	if (ref($entry->{domain}) eq "ARRAY") {
		$array = $entry->{domain};
	} elsif (ref($entry->{domain}) eq "HASH") {
		$array = [$entry->{domain}];
	} else {
		syslog(LOG_ERR, "domain key unknown type: %s: %s",
		  ref($entry->{domain}), Dumper($entry));
		return -1;
	}
	
	foreach $i (@$array) {
		$ret = db_add("domain", URI::_idna::encode(lc($i->{__text})));
		return $ret if ($ret < 0);
	}
	
	return 0;
}

sub block_entry_by_domainmasks
{
	my ($entry) = @_;
	my $array;
	my $i;
	my $str;
	my $ret;
	
	if (ref($entry->{domain}) eq "ARRAY") {
		$array = $entry->{domain};
	} elsif (ref($entry->{domain}) eq "HASH") {
		$array = [$entry->{domain}];
	} else {
		syslog(LOG_ERR, "domain key unknown type: %s: %s",
		  ref($entry->{domain}), Dumper($entry));
		return -1;
	}
	
	foreach $i (@$array) {
		$str = $i->{__text};
		if (substr($str, 0, 2) ne '*.') {
			syslog(LOG_ERR, "domain-mask entry not started with '*.': %s",
			  $i->{__text});
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
	my $array;
	my $i;
	my $ret;
	
	if (ref($entry->{ip}) eq "ARRAY") {
		$array = $entry->{ip};
	} elsif (ref($entry->{ip}) eq "HASH") {
		$array = [$entry->{ip}];
	} else {
		syslog(LOG_ERR, "ip key unknown type: %s: %s",
		  ref($entry->{ip}), Dumper($entry));
		return -1;
	}
	
	foreach $i (@$array) {
		$ret = db_add("ip-srv", $i->{__text});
		return $ret if ($ret < 0);
	}
	
	return 0;
}

sub block_entry_by_ipprefs
{
	my ($entry) = @_;
	my $array;
	my $i;
	my $ret;
	
	if (ref($entry->{ipSubnet}) eq "ARRAY") {
		$array = $entry->{ipSubnet};
	} elsif (ref($entry->{ipSubnet}) eq "HASH") {
		$array = [$entry->{ipSubnet}];
	} else {
		syslog(LOG_ERR, "ipSubnet key unknown type: %s: %s",
		  ref($entry->{ipSubnet}), Dumper($entry));
		return -1;
	}
	
	foreach $i (@$array) {
		$ret = db_add("ip-srv", $i->{__text});
		return $ret if ($ret < 0);
	}
	
	return 0;
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
	
	if ($opt_in) {
		$files = [ $opt_in ];
	} else {
		$req = new rknr_req(soap_uri => SOAP_URI, soap_ns => SOAP_NS,
		  req => $opt_req, sig => $opt_sig);
		syslog(LOG_INFO, "unpack the archive...");
		$files = get_file_from_zip($req->get_data(), TMPDIR."/data.zip");
		syslog(LOG_INFO, "archive is unpacked");
	}

	prework();
	
	syslog(LOG_INFO, "processing");
	foreach my $file (@$files) {
		$xmlp = new rknr_xmlp(file => $file);
	
		$ret = $xmlp->xml_parse();
	
		foreach $entry (@{$ret->{data}{"reg:register"}{content}}) {
			block_entry($entry);
		}
	}
	
	postwork();
}


######################################################################
# MAIN
######################################################################

proc_opts();

openlog("[rknr_get.pl]", "", SYSLOG_FACILITY);
syslog(LOG_INFO, "started");

eval {
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
