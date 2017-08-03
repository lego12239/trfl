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

    bless($self,$class);

    return $self;
}

sub _xml_start_tag
{
    my ($state, $e, $el, %attrs) = @_;
    my $el_num;
    my $tmp;

#print(Dumper(\@_));
    push(@{$state->{xmlel}}, { name => $el, attrs => {%attrs} });
    $el_num = $#{$state->{xmlel}};

#    if ( $el_num >= 1 ) {
	if ( ref(${$state->{cur}}) eq "" ) {
	    ${$state->{cur}} = {};
	}

	if ( defined(${$state->{cur}}->{$el}) ) {
	    if ( ref(${$state->{cur}}->{$el}) ne "ARRAY" ) {
		$tmp = ${$state->{cur}}->{$el};
		${$state->{cur}}->{$el} = [];
		${$state->{cur}}->{$el}[0] = $tmp;
	    }
	    push(@{${$state->{cur}}->{$el}}, {});
	    $tmp = $#{${$state->{cur}}->{$el}};
	    $state->{cur} = \(${$state->{cur}}->{$el}[$tmp]);
        } else {
	    ${$state->{cur}}->{$el} = {};
	    $state->{cur} = \(${$state->{cur}}->{$el});
	}
#    }
}

sub _xml_char_txt
{
    my ($state, $e, $str) = @_;
    my $el_num;


    $el_num = $#{$state->{xmlel}};
    $state->{xmlel}[$el_num]{el_char} .= $str;
}

sub _xml_get_cur
{
    my ($state) = @_;
    my $i;
    my $el_num;
    my $el_name;
    my $num;
    my $cur;


    $el_num = $#{$state->{xmlel}};

    $cur = \($state->{data});
    for($i = 0; $i <= $el_num; $i++) {
	$el_name = $state->{xmlel}[$i]{name};
	$cur = \($$cur->{$el_name});
        if ( ref($$cur) eq "ARRAY" ) {
	    $num = $#{$$cur};
	    $cur = \($$cur->[$num]);
        }
    }

    return $cur;
}

sub _xml_end_tag
{
    my ($state, $e) = @_;
    my $el_num;
    my $el;


    $el_num = $#{$state->{xmlel}};
    $el = pop(@{$state->{xmlel}});

#    if ( $el_num >= 1 ) {
    	${$state->{cur}}->{__text} = $el->{el_char};
    	${$state->{cur}}->{__attrs} = $el->{attrs};
#	if ( ref(${$state->{cur}}) ne "" ) {
#	    ${$state->{cur}}->{__char} = $el->{el_char};
#	} else {
#	    ${$state->{cur}} = $el->{el_char};
#	}
	$state->{cur} = _xml_get_cur($state);
#    }
}

sub xml_parse
{
    my $self = shift;
    my $state = {};
    my $hdlrs;
    my $xmlparser;


    $state->{data} = {};
    $state->{cur} = \(${state}->{data});
    $hdlrs = { Start => sub { _xml_start_tag($state, @_) },
	       End => sub { _xml_end_tag($state, @_) },
	       Char => sub { _xml_char_txt($state, @_) } };

    $xmlparser = new XML::Parser(Handlers => $hdlrs);
    $xmlparser->parsefile($self->{_file});

    return { data => $state->{data} };
}

1;
