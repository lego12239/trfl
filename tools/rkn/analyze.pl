#!/usr/bin/perl -I. -W

use strict;
use rknr_xmlp;
use Getopt::Long qw(:config gnu_getopt);
use Sys::Syslog qw(:standard :macros);
use Data::Dumper;


my $cnt = {
	total => 0,
	url => {
		total => 0,
		ewithout => 0,
		emore1 => 0},
	domain => {
		total => 0,
		ewithout => 0,
		emore1 => 0},
	ip => {
		total => 0,
		ewithout => 0,
		emore1 => 0},
	ipsubnet => {
		total => 0,
		ewithout => 0,
		emore1 => 0},
	blocktype => {
		default => 0,
		domain => 0,
		ip => 0,
		ipSubnet => 0,
		domain_mask => 0},
	scheme => {
		https => 0,
		http => 0,
		ftp => 0,
		others => 0},
	combo => {
		U_d => 0,
		U_D_ip => 0}};
my $ret;
my $entry;
my $xmlp;
my $dump_file;
my $scheme_others = {};
my ($fh_uris, $fh_domains);
my ($opt_u_out, $opt_d_all_out, $opt_d_out, $opt_dm_out, $opt_ip_out, $opt_ipsubnet_out);


sub report_err
{
	my ($msg) = @_;


	printf(STDERR "error: ".$msg."\n");
}

sub output_help
{
	print("Usage: analyze.pl [OPTIONS] DUMP_FILE\n\n".
	  "OPTIONS:\n".
	  " --u_out         output uris list\n".
	  " --d_all_out     output all entries domains\n".
	  " --d_out         output domains of block type domain\n".
	  " --dm_out        output domain masks list\n".
	  " --ip_out        output ips list\n".
	  " --ipsubnet_out  output ip prefixes list\n".
	  " -v, --version   show program version\n");
}

sub output_version
{
	print("analyze.pl 0-1.1\n");
}

sub proc_opts
{
	my $opt_h;
	my $opt_v;


	GetOptions(
		'u_out' => \$opt_u_out,
		'd_all_out' => \$opt_d_all_out,
		'd_out' => \$opt_d_out,
		'dm_out' => \$opt_dm_out,
		'ip_out' => \$opt_ip_out,
		'ipsubnet_out' => \$opt_ipsubnet_out,
		'help|h' => \$opt_h,
		'version|v' => \$opt_v);

	if ($opt_h) {
		output_help();
		exit(0);
	}
	
	if ($opt_v) {
		output_version();
		exit(0);
	}
	
	$dump_file = $ARGV[0];
	if (!defined($dump_file)) {
		report_err("Dump file isn't specified\n");
		exit(1);
	}
}

sub parse_entry
{
	my ($entry) = @_;
	
	if (!defined($entry->{__ATTRS}{blockType})) {
		$entry->{__ATTRS}{blockType} = "default";
	}
#	parse_url($entry);
#	parse_domain($entry);
#	parse_ip($entry);
#	parse_ipsubnet($entry);
}

sub parse_url
{
	my ($entry) = @_;

	return unless(defined($entry->{url}));	
}

sub parse_domain
{
	my ($entry) = @_;

	return unless(defined($entry->{domain}));	
}

sub parse_ip
{
	my ($entry) = @_;

	return unless(defined($entry->{ip}));	
}

sub parse_ipsubnet
{
	my ($entry) = @_;

	return unless(defined($entry->{ipsubnet}));	
}

sub analyze_url
{
	my $entry = shift;
	my $d;
	my $i;
	
	$d = $entry->{url};
	if (!defined($d)) {
		$cnt->{url}{ewithout}++;
		return;
	}
	$cnt->{url}{total} += $#$d + 1;
	$cnt->{url}{emore1}++ if ($#$d > 0);
}

sub analyze_domain
{
	my $entry = shift;
	my $d;
	my $i;
	
	$d = $entry->{domain};
	if (!defined($d)) {
		$cnt->{domain}{ewithout}++;
		return;
	}
	$cnt->{domain}{total} += $#$d + 1;
	$cnt->{domain}{emore1}++ if ($#$d > 0);
}

sub analyze_ip
{
	my $entry = shift;
	my $d;
	my $i;
	
	$d = $entry->{ip};
	if (!defined($d)) {
		$cnt->{ip}{ewithout}++;
		return;
	}
	$cnt->{ip}{total} += $#$d + 1;
	$cnt->{ip}{emore1}++ if ($#$d > 0);
}

sub analyze_ipsubnet
{
	my $entry = shift;
	my $d;
	my $i;
	
	$d = $entry->{ipsubnet};
	if (!defined($d)) {
		$cnt->{ipsubnet}{ewithout}++;
		return;
	}
	$cnt->{ipsubnet}{total} += $#$d + 1;
	$cnt->{ipsubnet}{emore1}++ if ($#$d > 0);
}

sub analyze_scheme
{
	my $entry = shift;
	my $i;
	my $scheme;
	
	if (!defined($entry->{url})) {
		return;
	}
	foreach $i (@{$entry->{url}}) {
		if ($i->{__TEXT} !~ /^([^:]+):/io) {
			die("Scheme not found: \n".Dumper($entry));
		}
		$scheme = lc($1);
		if ($scheme eq "https") {
			$cnt->{scheme}{https}++;
		} elsif ($scheme eq "http") {
			$cnt->{scheme}{http}++;
		} elsif ($scheme eq "ftp") {
			$cnt->{scheme}{ftp}++;
		} else {
			$cnt->{scheme}{others}++;
			$scheme_others->{$scheme} = 1;
		}
	}
}

sub analyze_combinations
{
	my $entry = shift;
	
	if ((!defined($entry->{url})) && (defined($entry->{domain}))) {
		$cnt->{combo}{U_d}++;
	}
	if ((!defined($entry->{url})) && (!defined($entry->{domain})) &&
	    (defined($entry->{ip}))) {
		$cnt->{combo}{U_D_ip}++;
	}
}

sub analyze_blocktype
{
	my $entry = shift;
	
	if ((!defined($entry->{__ATTRS}{blockType})) ||
	    ($entry->{__ATTRS}{blockType} eq "default")) {
		$cnt->{blocktype}{default}++;
	} elsif ($entry->{__ATTRS}{blockType} eq "domain") {
		$cnt->{blocktype}{domain}++;
	} elsif ($entry->{__ATTRS}{blockType} eq "ip") {
		if (defined($entry->{ip})) {
			$cnt->{blocktype}{ip}++;
		} elsif (defined($entry->{ipSubnet})) {
			$cnt->{blocktype}{ipSubnet}++;
		} else {
			die("analyze blocktype error: blocktype ip, but no ip or ".
			  "ipSubnet entry");
		}
	} elsif ($entry->{__ATTRS}{blockType} eq "domain-mask") {
		$cnt->{blocktype}{domain_mask}++;
	}
}

sub output_url
{
	my $entry = shift;
	my $i;

	foreach $i (@{$entry->{url}}) {
		printf("%s\n", $i->{__TEXT});
	}
}

sub output_domain_all
{
	my $entry = shift;
	my $i;

	if ($entry->{__ATTRS}{blockType} eq "domain-mask") {
		return;
	}
	foreach $i (@{$entry->{domain}}) {
		printf("%s\n", $i->{__TEXT});
	}
}

sub output_domain
{
	my $entry = shift;
	my $i;

	if ($entry->{__ATTRS}{blockType} ne "domain") {
		return;
	}
	foreach $i (@{$entry->{domain}}) {
		printf("%s\n", $i->{__TEXT});
	}
}

sub output_domain_mask
{
	my $entry = shift;
	my $i;

	if ($entry->{__ATTRS}{blockType} ne "domain-mask") {
		return;
	}
	foreach $i (@{$entry->{domain}}) {
		printf("%s\n", $i->{__TEXT});
	}
}

sub output_ip
{
	my $entry = shift;
	my $i;

	foreach $i (@{$entry->{ip}}) {
		printf("%s\n", $i->{__TEXT});
	}
}

sub output_ipsubnet
{
	my $entry = shift;
	my $i;

	foreach $i (@{$entry->{ipSubnet}}) {
		printf("%s\n", $i->{__TEXT});
	}
}

sub output_stat
{
	printf("Entries count: %d\n", $cnt->{total});
	printf("urls total: %d\n".
	  "Entries without url: %d\n".
	  "Entries with more than 1 url: %d\n",
	  $cnt->{url}{total}, $cnt->{url}{ewithout},
	  $cnt->{url}{emore1});
	printf("Domains total: %d\n".
	  "Entries without domains: %d\n".
	  "Entries with more than 1 domain: %d\n",
	  $cnt->{domain}{total}, $cnt->{domain}{ewithout},
	  $cnt->{domain}{emore1});
	printf("ip total: %d\n".
	  "Entries without ip: %d\n".
	  "Entries with more than 1 ip: %d\n",
	  $cnt->{ip}{total}, $cnt->{ip}{ewithout},
	  $cnt->{ip}{emore1});
	printf("ipsubnet total: %d\n".
	  "Entries without ipsubnet: %d\n".
	  "Entries with more than 1 ipsubnet: %d\n",
	  $cnt->{ipsubnet}{total}, $cnt->{ipsubnet}{ewithout},
	  $cnt->{ipsubnet}{emore1});
	printf("Scheme http: %d\n".
	  "Scheme https: %d\n".
	  "Scheme ftp: %d\n".
	  "Scheme others: %d(%s)\n",
	  $cnt->{scheme}{http}, $cnt->{scheme}{https}, $cnt->{scheme}{ftp},
	  $cnt->{scheme}{others}, join(", ", keys(%$scheme_others)));
	printf("Combinations: \n".
	  "  -url, +domain: %d\n".
	  "  -url, -domain, +ip: %d\n",
	  $cnt->{combo}{U_d}, $cnt->{combo}{U_D_ip});
	printf("blockType default: %d\n".
	  "blockType domain: %d\n".
	  "blockType ip: %d\n".
	  "blockType ipSubnet: %d\n".
	  "blockType domain-mask: %d\n",
	  $cnt->{blocktype}{default}, $cnt->{blocktype}{domain},
	  $cnt->{blocktype}{ip}, $cnt->{blocktype}{ipSubnet},
	  $cnt->{blocktype}{domain_mask});
}

sub main
{
	my ($url, $domain, $ip, $ipsubnet);
	
	$xmlp = new rknr_xmlp(file => $dump_file,
	  cb => {"/reg:register/content" => \&_proc_entry});
	$xmlp->xml_parse();

	if ((!$opt_u_out) && (!$opt_d_all_out) && (!$opt_d_out) && (!$opt_ip_out) &&
	    (!$opt_ipsubnet_out) && (!$opt_dm_out)) {
		output_stat();
	}
}

sub _proc_entry
{
	my ($entry) = @_;
	
	parse_entry($entry);
	if ($opt_u_out) {
		output_url($entry);
	} elsif ($opt_d_all_out) {
		output_domain_all($entry);
	} elsif ($opt_d_out) {
		output_domain($entry);
	} elsif ($opt_dm_out) {
		output_domain_mask($entry);
	} elsif ($opt_ip_out) {
		output_ip($entry);
	} elsif ($opt_ipsubnet_out) {
		output_ipsubnet($entry);
	} else {
		$cnt->{total}++;
		analyze_url($entry);
		analyze_domain($entry);
		analyze_ip($entry);
		analyze_ipsubnet($entry);
		analyze_scheme($entry);
		analyze_combinations($entry);
		analyze_blocktype($entry);
	}

	return 1;
}


######################################################################
# MAIN
######################################################################

binmode(STDOUT, ":utf8");

proc_opts();

eval {
	main();
};
if ($@) {
	report_err($@);
	exit(1);
}
exit(0);
