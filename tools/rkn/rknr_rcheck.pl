#!/usr/bin/perl -I. -W

use strict;
use rknr_xmlp;
use Getopt::Long qw(:config gnu_getopt no_ignore_case);
use URI;
use URI::_idna;
use Cwd;
use Text::CSV;
use Data::Dumper;


my $data = {};
my @files;
my $opt_verbose = 0;
my $opt_rdetails = 0;
my $opt_details = 0;


sub report_err
{
	my ($msg) = @_;


	print(STDERR "error: ".$msg."\n");
}

sub output_help
{
	print("Usage: rknr_rcheck.pl [OPTIONS] REVIZOR_REPORT ".
	  "REGISTRIES_PREFIXES\n\n".
	  "Options:\n".
	  " -h, --help            show help\n".
	  " -V, --version         show program version\n".
	  " -v, --verbose         show progress info\n".
	  " -s, --show-rdetails   show revizor failure details\n".
	  " -S, --show-details    show register entry details\n".
	  "REVIZOR_REPORT         csv report file\n".
	  "REGISTRIES_PREFIXES    files prefixes separated with space\n".
	  "                       e.g. for backup/dump all backup/dump* will be ".
	  "used\n");
}

sub output_version
{
	print("rknr_rcheck.pl 0-1.0\n");
}

sub proc_opts
{
	my ($opt_h, $opt_V, $opt_v);

	GetOptions('help|h' => \$opt_h,
	  'version|V' => \$opt_V,
	  'verbose|v' => \$opt_verbose,
	  'show-rdetails|s' => \$opt_rdetails,
	  'show-details|S' => \$opt_details);

	if ( $opt_h ) {
		output_help();
		exit(0);
	}
	
	if ($opt_V) {
		output_version();
		exit(0);
	}
}

sub info_out
{
	my ($fmt) = shift(@_);
	
	return unless ($opt_verbose);
	printf($fmt."\n", @_);
}

sub reset_data_counters
{
	my $id;
	my @ids;
	
	@ids = keys(%$data);
	foreach $id (@ids) {
		$data->{$id}{found} = 0;
	}
	
}

sub load_rdata
{
	my ($file) = @_;
	my $fh;
	my $csv;
	my $row;
	my $is_body = -1;
	
	if ((!defined($file)) || ($file eq "")) {
		die("REVIZOR_REPORT isn't specified");
	}
	unless (open($fh, "<:encoding(cp1251)", $file)) {
		die("$file open error: $!");
	}
	$csv = Text::CSV->new({binary => 1, sep_char => ";", decode_utf8 => 1});
	if (!$csv) {
		die("$file: can't create csv instance");
	}
	# omit a header
	while (defined($row = $csv->getline($fh))) {
		$is_body++ if (($row->[0] eq "") || ($is_body >= 0));
		last if ($is_body == 2);
	}
	if ((0 + $csv->error_diag())) {
		die("$file: ".$csv->error_diag());
	}
	# read a body
	while (defined($row = $csv->getline($fh))) {
		if (!defined($data->{$row->[4]})) {
			$data->{$row->[4]} = {
				rchecks => [],
				regs => []};
		}
		
		push(@{$data->{$row->[4]}{rchecks}}, {
			time => $row->[0],
			node => $row->[1],
			node_addr => $row->[2],
			node_coord => $row->[3],
			id => $row->[4],
			req => $row->[5],
			id_org => $row->[6],
			id_time => $row->[7],
			http_code => $row->[8],
			http_redir => $row->[9]});
	}
	if (((0 + $csv->error_diag()) != 2012) &&
	    ((0 + $csv->error_diag()) != 0)) {
		die("$file: ".(0 + $csv->error_diag()));
	}
	close($fh);
}

sub get_files_list
{
	my $pref;
	my @files;
	my @sorted;
	
	foreach $pref (@_) {
		push(@files, glob($pref."*"));
	}
	@sorted = sort(@files);
	
	return @sorted;
}

sub collect_info
{
	my $file;
	my $id;
	my @ids;
	my $info;
	my $xmlp;
	
	info_out("collect info");
	@ids = keys(%$data);
	foreach $file (@_) {
		next unless (-f $file);
		reset_data_counters();
		foreach $id (@ids) {
			$info = {
				file => {
					name => $file,
					exist => 0},
				entry => undef};					
			push(@{$data->{$id}{regs}}, $info);
		}
		$xmlp = new rknr_xmlp(file => $file,
		  cb => {"/reg:register/content" => sub {
		    return _proc_entry(\@ids, @_)}});
		$xmlp->xml_parse();

		info_out("%s is read", $file);
	}
}

sub _proc_entry
{
	my ($ids, $entry) = @_;
	my $id;
	my $info;
	
	foreach $id (@$ids) {
		next if ($data->{$id}{found});
		if ($id eq $entry->{__ATTRS}{id}) {
			$data->{$id}{found} = 1;
			$info = $data->{$id}{regs}[$#{$data->{$id}{regs}}];
			$info->{file}{exist} = 1;
			$info->{entry} = clone_entry($entry);
		}
	}
	
	return 1;
}

sub clone_entry
{
	my ($entry) = @_;
	my $e = {};
	my @keys;
	my $i;
	
	@keys = keys(%{$entry->{__ATTRS}});
	foreach $i (@keys) {
		$e->{__ATTRS}{$i} = $entry->{__ATTRS}{$i};
	}

	@keys = keys(%{$entry->{decision}[0]{__ATTRS}});
	foreach $i (@keys) {
		$e->{decision}[0]{__ATTRS}{$i} = $entry->{decision}[0]{__ATTRS}{$i};
	}

	if (defined($entry->{url})) {
		$e->{url} = _clone_entry_fields($entry->{url});
	}

	if (defined($entry->{domain})) {
		$e->{domain} = _clone_entry_fields($entry->{domain});
	}

	if (defined($entry->{ip})) {
		$e->{ip} = _clone_entry_fields($entry->{ip});
	}

	if (defined($entry->{ipSubnet})) {
		$e->{ipSubnet} = _clone_entry_fields($entry->{ipSubnet});
	}
	
	return $e;
}

sub _clone_entry_fields
{
	my ($f) = @_;
	my $i;
	my $ret = [];
	
	foreach $i (@$f) {
		push(@$ret, {__TEXT => $i->{__TEXT}});
	}
	
	return $ret;
}

sub show_info
{
	my @ids;
	my $id;
	my $i;
	
	@ids = keys(%$data);
	foreach $id (@ids) {
		printf("%s\n  failures:\n", $id);
		foreach $i (@{$data->{$id}{rchecks}}) {
			printf("    %s\n", $i->{time});
			if ($opt_rdetails) {
				printf("      %s (%s, %s)\n", $i->{req}, $i->{http_code},
				  $i->{http_redir});
			}
		}
		printf("\n  registries:\n");
		foreach $i (@{$data->{$id}{regs}}) {
			printf("    %s %s\n", $i->{file}{name},
			  $i->{file}{exist} ? "PRESENT": "absent");
			if ($opt_details) {
				show_entry($i->{entry});
			}
		}
		printf("\n\n");
	}
}

sub show_entry
{
	my ($entry) = @_;
	my @keys;
	my $i;
	
	@keys = keys(%{$entry->{__ATTRS}});
	foreach $i (@keys) {
		printf("      %s=%s\n", $i, $entry->{__ATTRS}{$i}); 
	}

	print("      decision: ");
	@keys = keys(%{$entry->{decision}[0]{__ATTRS}});
	foreach $i (@keys) {
		printf("%s=%s ", $i, $entry->{decision}[0]{__ATTRS}{$i}); 
	}
	print("\n");

	if (defined($entry->{url})) {
		print("      url:\n");
		_show_entry_fields($entry->{url});
	}

	if (defined($entry->{domain})) {
		print("      domain:\n");
		_show_entry_fields($entry->{domain});
	}

	if (defined($entry->{ip})) {
		print("      ip:\n");
		_show_entry_fields($entry->{ip});
	}

	if (defined($entry->{ipSubnet})) {
		print("      ipSubnet:\n");
		_show_entry_fields($entry->{ipSubnet});
	}
}

sub _show_entry_fields
{
	my ($f) = @_;
	my $i;
	
	foreach $i (@$f) {
		printf("        %s\n", $i->{__TEXT});
	}
}


######################################################################
# MAIN
######################################################################

binmode(STDOUT, ":utf8");

proc_opts();

load_rdata(shift(@ARGV));
@files = get_files_list(@ARGV);
collect_info(@files);
show_info();
