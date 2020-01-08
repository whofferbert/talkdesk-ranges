#!/usr/bin/env perl
# Copyright (c) 2019 William Hofferbert
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#
# Iterate over Talkdesk names and associated services to return a complete 
# list of CIDR ranges for routing.
#
# This script pulls data from the web (requires internet connection) regarding
# current talkdesk IP ranges. Caches data from successful runs, to use in case
# pages do not respond in a timely manner.
#

use 5.010;				# say
use strict;				# good form
use warnings;				# know when stuff is wrong
#
#use Data::Dumper;			# for debugging
#$Data::Dumper::Sortkeys = 1;		# sort the dumped hash keys
#
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
my $google_cloud_record = "_cloud-netblocks.googleusercontent.com";

# WWW caching
my %www_file_cache_names = (
  $talkdesk_range_url => "talkdesk_ranges",
  $talkdesk_names_url => "talkdesk_names",
  $aws_ip_url => "aws_ips",
  $cloudflare_ip_url => "cloudflare_ips",
  $google_cloud_record => "google_ips",
);

my $caller_uid = $>;
my $www_cache_dir = "/var/tmp/talkdesk-ranges.$caller_uid/";

# store www page calls in memory
my %www_data;
my $www_fetch_timeout_secs = 5;

# ipv4 and/or 6
my ($ipv4, $ipv6);

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
        "corp", to pull IPs for corp.mytalkdesk.com and friends.

    -a -aws-range "string"
        Provide the AWS ranges to match against. Default is: $default_range_str
        Can be provided multiple times to return all the appropriate ranges.
        For example: us-east, eu-north, GLOBAL, etc.

    -n -nameserver "IP"
        Query a specific DNS nameserver instead of the default one.

    -t -tcp
        Do TCP based DNS lookups insted of UDP

    -c -www-cache-dir "/path/to/dir"
        Use a non-standard dir for caching calls.
        Default is $www_cache_dir

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

    say $usage;
    exit(0);
}

sub handle_args {
    Getopt::Long::GetOptions(
        's|signifier=s' => \$signifier,
        'a|aws-range=s' => sub {push(@aws_range_names, $_[1])},
        'n|nameserver=s' => \$dns_nameserver,
        't|tcp' => sub {$dns_protocol = "TCP"},
        'c|www-cache-dir=s' => \$www_cache_dir,
        '4' => sub { $ipv4 = 1 },
        '6' => sub { $ipv6 = 1 },
        'h|help' => \&usage,
    );
}

sub warn {
    my $msg=shift;
    say STDERR $msg;
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
    if (! defined $ipv4 && ! defined $ipv6) {
        $ipv4 = 1;
    }
    mkdir $www_cache_dir if ! -d $www_cache_dir;
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
    # works for ranges in ranges too
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
    # argument is a list of names
    # return is a list of IPs
    my @ips;
    for my $lookup_name (@_) {
        if ($ipv4) {
            push(@ips, &dig_it($lookup_name, 'a'));
        }
        if ($ipv6) {
            push(@ips, &dig_it($lookup_name, 'aaaa'));
        }
    }
    return @ips;
}

sub www_disk_cache_write {
    my ($url, $data) = @_;
    my $fileName = $www_file_cache_names{$url};
    open my $FH, ">", $www_cache_dir . $fileName;
    print $FH $data;
    close $FH;
}

sub www_disk_cache_read {
    my ($url) = @_;
    my $data;
    my $file = $www_cache_dir . $www_file_cache_names{$url};
    return unless -f $file;
    open my $FH, "<", $file;
    {
        local $/ = undef;
        $data = <$FH>;
    }
    close $FH;
    return $data;
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
        # enforce hostname verification
        $ua->ssl_opts( verify_hostname => 1);
        my $req = $ua->get($url);
        if ($req->is_success) {
            my $data = $req->content;
            $www_data{$url} = $data;
            &www_disk_cache_write($url, $data);
            return $data;
        } else {
            my $data = &www_disk_cache_read($url);
            return $data if defined $data;
        }
    }
    # if none above works, it's undef
}

sub talkdesk_names {
    my $data = &pull_www_data($talkdesk_names_url);
    if (! defined $data) {
        &warn("Unable to pull Talkdesk names");
        return;
    }
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
        # TODO this explicitly skips *pusher.com
        next unless $name =~ /^\*\./;
        push(@return, &dig_names($signifier . "." . $name));
    }
    return @return;
}

sub talkdesk_ranges {
    # pull data from live site...
    my $data = &pull_www_data($talkdesk_range_url);
    if (! defined $data) {
        &warn("Unable to pull Talkdesk ranges");
        return;
    }
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
    my $data = &pull_www_data($aws_ip_url);
    if (! defined $data) {
        &warn("Unable to pull AWS ranges");
        return;
    }
    my $aws_obj  = decode_json $data;
    my $aws_create_date = $aws_obj->{createDate};
    if ($ipv4) {
        for my $range (@{$aws_obj->{prefixes}}) {
            if (grep {$range->{region} =~ /$_/i} @aws_range_names ) {
                push(@ranges, $range->{ip_prefix});
            }
        }
    }
    if ($ipv6) {
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
    if (! defined $data) {
        &warn("Unable to pull Cloudflare ranges");
        return;
    }
    my @ranges = split(/\n/, $data);
    return @ranges;
}

sub ip4_ip6_from_spf {
    my ($include) = @_;
    my @ret;
    my $data = (&dig_it($include, "txt"))[0];
    while ($data =~ /(?<=include:)(\S+)[\s$ ]/gx) {
        push(@ret, &ip4_ip6_from_spf($1));
    }
    if ($ipv4) {
        while ($data =~ /(?<=ip4:)(\S+)[\s$ ]/gx) {
            push(@ret, $1);
        }
    }
    if ($ipv6) {
        while ($data =~ /(?<=ip6:)(\S+)[\s$ ]/gx) {
            push(@ret, $1);
        }
    }
    return @ret;
}

sub google_compute_cloud_ranges {
    my @ret;
    # TODO any way to cache this? not without a lot of adjustment
    # i suppose we should just rely on the spf info being there
    push(@ret, &ip4_ip6_from_spf($google_cloud_record));
    return @ret;
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

sub sort_ipv4 {
    my @sorted;
    my %h;
    my @octets = @_;
    for my $range (@octets) {
        if ($range =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d+)/) {
            $h{$1}{$2}{$3}{$4}{$5}++;
        }
    }
    for my $one (sort {$a<=>$b} keys %h) {
        for my $two (sort {$a<=>$b} keys %{$h{$one}}) {
            for my $three (sort {$a<=>$b} keys %{$h{$one}{$two}}) {
                for my $four (sort {$a<=>$b} keys %{$h{$one}{$two}{$three}}) {
                    for my $five (sort {$a<=>$b} keys %{$h{$one}{$two}{$three}{$four}}) {
                        push(@sorted, "$one.$two.$three.$four/$five");
                    }
                }
            }
        }
    }
    return @sorted;
}

sub get_ranges {
    my @ranges;
    
    push(@ranges, &google_compute_cloud_ranges);
    push(@ranges, &cloudflare_ranges) if $ipv4;
    push(@ranges, &aws_ranges);
    push(@ranges, &talkdesk_ranges) if $ipv4;
    push(@ranges, &talkdesk_names);

    # only report on unique ranges
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

    my @ret;

    # exclude ranges that exist in other ranges
    push(@ret, &sort_ipv4(&unique_ranges(@ipv4_cidr)));
    push(@ret, &unique_ranges(@ipv6_cidr));

    # return output sorted by octets
    return(@ret);
}

sub main {
    &handle_args;		# deal with arguments
    &sanity;			# make sure things make sense
    map {say} (&get_ranges);	# do the thing
}

&main;
