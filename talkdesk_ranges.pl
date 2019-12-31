#!/usr/bin/env perl
# by William Hofferbert
#  
# Iterate over Talkdesk names to return a complete list of CIDR ranges for routing.
#
# This script pulls data from the web (requires internet connection) regarding
# current talkdesk IP ranges
#
# TODO backup ranges/names if pages unavailable?

use 5.010;				# say
use strict;				# good form
use warnings;				# know when stuff is wrong

use Data::Dumper;			# for debugging
$Data::Dumper::Sortkeys = 1;		# sort the dumped hash keys

use File::Basename;			# know where the script lives
use Getopt::Long;			# handle arguments
use LWP::UserAgent;			# www calls
use JSON::PP;				# pure-perl JSON encoder/decoder
use NetAddr::IP;			# range logic
use NetAddr::IP::Util 
    qw(inet_ntoa ipv6_ntoa);		# binary to human readable
use Net::DNS::Dig;			# get dns info based on names

#
# Default Variables
#

my $prog = basename($0);
my $signifier;

my $user_agent = "Mozilla/5.0";

# URLs with CIDR/name info
my $talkdesk_range_url = "https://support.talkdesk.com/hc/en-us/articles/210173043-Quality-of-Service-QoS-Media-IP-ranges-for-traffic-shaping-at-your-firewall";
my $talkdesk_names_url = "https://support.talkdesk.com/hc/en-us/articles/204370859-Setting-up-System-Requirements-and-Network-Settings";
my $aws_ip_url = "https://ip-ranges.amazonaws.com/ip-ranges.json";
my $cloudflare_ip_url = "https://www.cloudflare.com/ips-v4";

# store www page calls in memory
my %www_data;
my $www_fetch_timeout_secs = 5;

# ipv4 and/or 6
my @protocols;

# how to ask for things in dns
my $dns_protocol = "UDP";
my $dns_nameserver;

# array to hold wanted aws names
my @aws_range_names;
my @default_aws_range = ("us-east", "us-west", "GLOBAL");

#
# Functions
#

sub usage {
    my $default_range_str = join", ", @default_aws_range;
    my $usage = <<"    END_USAGE";

  This program lists out ranges that could be associated with Talkdesk for Callbar software.
  These ranges include explicit Talkdesk resources, AWS, Cloudflare, and Google Compute Cloud ranges.

  Basic Usage: $prog -s 'signifier' -a 'aws-range'

  Options:

    -s -signifier "string"
        Provide a signifier to use with name extrapolation, ie
        "corp", to pull corp.mytalkdesk.com

    -a -aws-range "string"
        Provide the AWS ranges to match against. Default is: $default_range_str
        Can be provided multiple times to return all the appropriate ranges.
        For example: us-east, eu-north, GLOBAL, etc.

    -n -nameserver "IP"
        Query a specific DNS nameserver instead of the default one.

    -t -tcp
        Do TCP based DNS lookups insted of UDP

    -4 
        Print IPv4 ranges (default)

    -6
        Print IPv6 ranges

    -h -help
        Summon a sentient, angry tuba.

  Examples:

    Generate a list of CIDR ranges for the talkdesk domain 'example'
      $prog -s 'example'

    Get the list with a non-default set of AWS ranges:
      $prog -s 'example' -a 'eu-north' -a 'GLOBAL'

    END_USAGE

    print "$usage";
    exit(0);
}

sub handle_args {
    Getopt::Long::GetOptions(
        's|signifier=s' => \$signifier,
        'a|aws-range=s' => sub {push(@aws_range_names, $_[1])},
        'n|nameserver=s' => \$dns_nameserver,
        't|tcp' => sub {$dns_protocol = "TCP"},
        '4' => sub {push(@protocols, 4)},
        '6' => sub {push(@protocols, 6)},
        'h|help' => \&usage,
    );
}


sub err {
    my $msg=shift;
    say STDERR $msg;
    exit 2;
}

sub sanity {
    &err("$prog requires a signifier! See $prog -help for more info.") unless defined $signifier;
    # use defaults unless things were provided
    @aws_range_names = @default_aws_range unless @aws_range_names;
    @protocols = (4) unless @protocols;
}

sub dig_it {
    my ($record, $type) = @_;
    return unless ($record =~ /.+/);
    my (@ret, $dig);

    if ($dns_nameserver) {
        $dig = Net::DNS::Dig->new(Proto => $dns_protocol, PeerAddr => $dns_nameserver)->for($record, $type)->data();
    } else {
        $dig = Net::DNS::Dig->new(Proto => $dns_protocol)->for($record, $type)->data();
    }

    for my $hash (@$dig) {
        # RDLEN = 4 && TYPE = 1 => A record.
        if ($hash->{RDLEN} == 4 && $hash->{TYPE} == 1) {
            map { push (@ret, inet_ntoa($_)) } @{$hash->{RDATA}};
        # RDLEN = 16 && TYPE = 28 => AAAA record.
        } elsif ($hash->{RDLEN} == 16 && $hash->{TYPE} == 28) {
            map { push (@ret, ipv6_ntoa($_)) } @{$hash->{RDATA}};
        # txt records, just concatenate
        } elsif ($hash->{TYPE} == 16) {
            push (@ret, join"", @{$hash->{RDATA}});
        }
    }

    return(@ret);
}

sub ip_in_range {
    my ($ip, $range) = @_;
    my $checkObj = NetAddr::IP->new( $ip );
    my $net = NetAddr::IP->new( $range );
    if ( $net->contains($checkObj) ) {
        return 1;
    } else {
        return 0;
    }
}

sub dig_names {
    # ipv4 vs ipv6
    my @ips;
    for my $lookup_name (@_) {
        if (grep {$_ eq 4} @protocols) {
            push(@ips, &dig_it($lookup_name, 'a'));
        }
        if (grep {$_ eq 6} @protocols) {
            push(@ips, &dig_it($lookup_name, 'aaaa'));
        }
    }
    return @ips;
}

sub pull_www_data {
    my ($url) = @_;
    if (exists $www_data{$url}) {
        return($www_data{$url});
    } else {
        my $ua = new LWP::UserAgent (
            agent => $user_agent, 
            cookie_jar =>{}, 
            timeout => $www_fetch_timeout_secs);
        my $data = $ua->get($url)->content;
        $www_data{$url} = $data;
        return $data;
    }
}

sub talkdesk_names {
    my $data = &pull_www_data($talkdesk_names_url);
    my @names;
    # TODO this relies on their html formatting and therefore sucks
    # could probably be better...
    while ($data =~ /li..span.*?(([\w\*-]+\.)+(com|io))/g) {
        push(@names, $1);
    }
    my @return;
    # handle static names
    for my $name (@names) {
        next if $name =~ /^\*/;
        push(@return, &dig_names($name));
    }
    # handle variable names
    for my $name (@names) {
        # this explicitly skips *pusher.com
        next unless $name =~ /^\*\./;
        push(@return, &dig_names($signifier . "." . $name));
    }
    return @return;
}

sub talkdesk_ranges {
    # pull data from live site...
    my $data = &pull_www_data($talkdesk_range_url);
    my @ranges;
    # TODO sanity check we get correct ranges, ie octets between 0-255 and ranges between 0 and 32
    while ($data =~ /((?:\d{1,3}\.){3}\d{1,3}\/\d+)/g) {
        push(@ranges, $1);
    }
    return @ranges;
}

sub aws_ranges {
    # filter by aws range name parts (regex)
    my @ranges;
    my $aws_obj  = decode_json &pull_www_data($aws_ip_url);
    my $aws_create_date = $aws_obj->{createDate};
    if (grep {$_ eq 4} @protocols) {
        for my $range (@{$aws_obj->{prefixes}}) {
            if (grep {$range->{region} =~ /$_/i} @aws_range_names ) {
                push(@ranges, $range->{ip_prefix});
            }
        }
    }
    if (grep {$_ eq 6} @protocols) {
        for my $range (@{$aws_obj->{ipv6_prefixes}}) {
            if (grep {$range->{region} =~ /$_/i} @aws_range_names ) {
                push(@ranges, $range->{ipv6_prefix});
            }
        }
    }
    return(@ranges);
}

sub cloudflare_ranges {
    my $data = &pull_www_data($cloudflare_ip_url);
    my @ranges = split(/\n/, $data);
    return @ranges;
}


sub unique_ranges {
    my %h;
    for my $range (@_) {
        if ($range =~ /^(.*?)\/(\d+)$/) {
            push(@{$h{$2}}, $1);
        }
    }

    my (@ascending, @descending, @ret);
    for my $range (sort {$a < $b} keys %h) {
        map {push(@ascending, "$_/$range")} @{$h{$range}};
    }
    @descending = reverse @ascending;

    for my $range (@ascending) {
        my $matched = 0;
        for my $check (@descending) {
            # don't be true if we are checking the same range
            next if $check eq $range;
            next if $matched == 1;
            $matched = 1 if &ip_in_range($range, $check);
        }
        push(@ret, $range) if $matched == 0;
    }

    return @ret;
}

sub ip4_ip6_from_spf {
    my ($include) = @_;
    my @ret;
    my $data = (&dig_it($include, "txt"))[0];
    while ($data =~ /(?<=include:)(\S+)[\s$ ]/gx) {
        push(@ret, &ip4_ip6_from_spf($1));
    }
    if (grep {$_ eq 4} @protocols) {
        while ($data =~ /(?<=ip4:)(\S+)[\s$ ]/gx) {
            push(@ret, $1);
        }
    }
    if (grep {$_ eq 6} @protocols) {
        while ($data =~ /(?<=ip6:)(\S+)[\s$ ]/gx) {
            push(@ret, $1);
        }
    }
    return @ret;
}

sub google_compute_cloud_ranges {
    my @ret;
    push(@ret, &ip4_ip6_from_spf("_cloud-netblocks.googleusercontent.com"));
    # this came up in callbar connections, but not in the googleusercontent.com lookup
    # TODO determine how to pull this dynamically
    push(@ret, "172.217.164.0/23") if grep {$_ eq 4} @protocols;;
    return @ret;
}

sub get_ranges {
    my @ranges;
    
    push(@ranges, &google_compute_cloud_ranges);
    push(@ranges, &cloudflare_ranges) if grep {$_ eq 4} @protocols;
    push(@ranges, &aws_ranges);
    push(@ranges, &talkdesk_ranges) if grep {$_ eq 4} @protocols;
    push(@ranges, &talkdesk_names);

    # ranges
    my %uniq;
    map {$uniq{$_}++} @ranges;
    my @sort_ranges = sort keys %uniq;
    my @ipv4_cidr = grep {$_ =~ /^[^:]+\/\d+$/} @sort_ranges;
    my @ipv6_cidr = grep {$_ =~ /^[^.]+\/\d+$/} @sort_ranges;

    # eliminate individual IPs that are in ranges we know about
    my @ipv4_addr;
    for my $ip (grep {$_ =~ /^[^:\/]+$/} @sort_ranges) {
        # if it exists in any ipv4 range, don't report it
        my $matched = 0;
        for my $range (@ipv4_cidr) {
            $matched = 1 if &ip_in_range($ip, $range);
        }
        push(@ipv4_addr, $ip) if $matched == 0;
    }
    my @ipv6_addr;
    for my $ipv6 (grep {$_ =~ /^[^.\/]+$/} @sort_ranges) {
        my $matched = 0;
        for my $range (@ipv6_cidr) {
            $matched = 1 if &ip_in_range($ipv6, $range);
        }
        push(@ipv6_addr, $ipv6) if $matched == 0;
    }

    # make single IPs into cidr notation
    for my $ip (@ipv4_addr) {
        push(@ipv4_cidr, $ip . "/32");
    }
    for my $ipv6 (@ipv6_addr) {
        push(@ipv6_cidr, $ipv6 . "/64");
    }

    # exclude ranges that exist in other ranges
    @ipv4_cidr = &unique_ranges(@ipv4_cidr);
    @ipv6_cidr = &unique_ranges(@ipv6_cidr);

    return (@ipv4_cidr, @ipv6_cidr);
}

sub main {
    &handle_args;		# deal with arguments
    &sanity;			# make sure things make sense
    map {say} (&get_ranges);	# do the thing
}

&main;
