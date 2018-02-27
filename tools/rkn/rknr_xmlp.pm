package rknr_xmlp;


use strict;
use XML::Parser;
use Encode;
use Data::Dumper;


sub new
{
	my $class = shift;
	my %p = @_;
	my $self = {};

	$self->{_file} = $p{file};
	if (defined($p{cb})) {
		$self->{_cb} = $p{cb};
	} else {
		$self->{_cb} = {};
	}

	bless($self,$class);

	return $self;
}

sub _xml_start_tag
{
	my ($state, $e, $el, %attrs) = @_;

#print(Dumper(\@_));
	if (!defined($state->{cur}[0]{$el})) {
		$state->{cur}[0]{$el} = [];
	}
	unshift(@{$state->{cur}}, {__ATTRS => {%attrs}});
	push(@{$state->{cur}[1]{$el}}, $state->{cur}[0]);
	push(@{$state->{name}}, $el);
}

sub _xml_char_txt
{
	my ($state, $e, $str) = @_;

	$state->{cur}[0]{__TEXT} .= $str;
}

sub _xml_mk_cur_fullname
{
	my ($state) = @_;
	my $i;
	my $str;
	my $ret = "";

	foreach $i (@{$state->{name}}) {
		$str = $i;
		$str =~ s/\//\\\//go;
		$ret .= "/".$str;
	}

	return $ret;
}

sub _xml_end_tag
{
	my ($state, $e) = @_;
	my $name;
	my $fullname;
	my $cur;
	my $ret;

	$fullname = _xml_mk_cur_fullname($state);
	$name = pop(@{$state->{name}});
	$cur = shift(@{$state->{cur}});
	
	if (defined($state->{cb}{$fullname})) {
		$ret = $state->{cb}{$fullname}($cur);
		if ($ret == 1) {
			pop(@{$state->{cur}[0]{$name}});
		} elsif ($ret == 2) {
			$e->finish();
		}
	}
}

sub xml_parse
{
	my $self = shift;
	my $state = {};
	my $hdlrs;
	my $xmlparser;


	$state->{data} = {};
	$state->{cur} = [$state->{data}];
	$state->{name} = [];
	$state->{cb} = $self->{_cb};
	$hdlrs = { Start => sub { _xml_start_tag($state, @_) },
		   End => sub { _xml_end_tag($state, @_) },
		   Char => sub { _xml_char_txt($state, @_) } };

	$xmlparser = new XML::Parser(Handlers => $hdlrs);
	$xmlparser->parsefile($self->{_file});

	return $state->{data};
}

1;
