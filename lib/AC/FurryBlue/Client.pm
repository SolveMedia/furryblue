# -*- perl -*-

# Copyright (c) 2009 AdCopy
# Author: Jeff Weisberg
# Created: 2009-Apr-07 11:37 (EDT)
# Function: for other programs to talk to fbdb

package AC::FurryBlue::Client;
use AC::Yenta::Conf;
use AC::DC::Protocol;
use AC::DataCenter;
use AC::Import;
use AC::Dumper;
use AC::Misc;
use Sys::Hostname;
use JSON;
use Digest::SHA 'sha1';
use Digest::MD5 'md5';
use Socket;
use strict;

require 'AC/FurryBlue/proto/y2db_status.pl';
require 'AC/FurryBlue/proto/y2db_check.pl';
require 'AC/FurryBlue/proto/y2db_getset.pl';
require 'AC/FurryBlue/proto/y2db_ring.pl';

our @EXPORT = 'timet_to_yenta_version';	# imported from Y/Conf

my $HOSTNAME = hostname();
my $OLDAGE   = 600;

my %MSGTYPE =
 (
  y2db_status		=> { num => 32, reqc => 'ACPY2StatusRequest', resc => 'ACPY2StatusReply' },
  y2db_get		=> { num => 33, reqc => 'ACPY2GetSet',        resc => 'ACPY2GetSet' },
  y2db_distrib		=> { num => 34, reqc => 'ACPY2DistRequest',   resc => 'ACPY2DistReply' },
  y2db_check		=> { num => 35, reqc => 'ACPY2CheckRequest',  resc => 'ACPY2CheckReply' },
  y2db_ringcf		=> { num => 36, reqc => 'ACPY2RingConfReq',   resc => 'ACPY2RingConfReply' },
 );

for my $name (keys %MSGTYPE){
    my $r = $MSGTYPE{$name};
    AC::DC::Protocol->add_msg( $name, $r->{num}, $r->{reqc}, $r->{resc});
}


# one or more of:
#   new( seed )
#   new( server_file )

sub new {
    my $class = shift;
    my $map   = shift;

    my $me         =  bless {
        map        => $map,
        debug      => sub{ },
        proto      => AC::DC::Protocol->new(),
        datacenter => my_datacenter(),
        copies     => 1,

        # servers { id => {addr, port, ...} }
        # mapservers []	 - have our map
        # allservers []  - all servers
        # ringcf  [ ]
        @_,
    }, $class;

    die "servers or server_file?\n" unless $me->{seed} || $me->{server_file};

    if( $me->{server_file} ){
        $me->_read_serverfile($map);
    }

    # RSN - seed[]

    return $me;
}

################################################################

# yentad saves a list of alternate peers to try in case it dies
sub _read_serverfile {
    my $me  = shift;
    my $map = shift;

    my $f;
    open($f, $me->{server_file});
    local $/ = "\n";

    while(<$f>){
        chop;
        my $data = decode_json( $_ );
        next unless $data->{subsystem} eq 'furryblue';
        next if $me->{env} && $me->{env} ne $data->{environment};

        my $id = $data->{id};
        $me->{servers}{$id} = $data;
    }

    $me->_make_server_list();
}

sub _make_server_list {
    my $me = shift;

    my @s = values %{$me->{servers}};
    shuffle(\@s);

    # local first
    @s = sort {
        $b->{is_local} <=> $a->{is_local}
    } @s;

    $me->{allservers} = \@s;
}

# fetch server list from server
sub _read_server_list {
    my $me = shift;

    my @s = @{$me->{allservers}};

    $me->{debug}->("fetching server list");

    my $req = $me->{proto}->encode_request( {
        type		=> 'y2db_status',
        msgidno		=> rand(0xFFFFFFFF),
        want_reply	=> 1,
    }, {} );

    my $res = $me->_send_request( \@s, $req );
    return unless $res;

    my @ms;

    for my $r ( @{$res->{data}{status}} ){
        next if $me->{env} && $me->{env} ne $r->{environment};
        my $id = $r->{server_id};
        my $s = {
            id		=> $id,
            is_local	=> ($r->{datacenter} eq $me->{datacenter}),
        };

        my $best;
        for my $ip ( @{$r->{ip}} ){
            next if $ip->{natdom} && $ip->{natdom} ne $me->{datacenter};
            $best ||= $ip;
            $best = $ip if $ip->{natdom};
        }
        $s->{addr} = inet_itoa($best->{ipv4});
        $s->{port} = $best->{port};
        $me->{servers}{$id} = $s;

        if( $s->{is_local} && grep { $me->{map} eq $_ } @{$r->{database}} ){
            push @ms, $s;
        }
    }

    $me->{servertime} = time();
    $me->{mapservers} = \@ms if @ms;
    $me->_make_server_list();
}

sub _read_ringcf {
    my $me = shift;

    $me->{debug}->("fetching ring config");

    my @s = @{$me->{allservers}};
    my $req = $me->{proto}->encode_request( {
        type		=> 'y2db_ringcf',
        msgidno		=> rand(0xFFFFFFFF),
        want_reply	=> 1,
    }, {
        map		=> $me->{map},
        datacenter	=> $me->{datacenter},
    } );

    my $res = $me->_send_request( \@s, $req );

    $me->{ringtime} = time();

    return unless $res;	# not sharded
    return if $res->{data}{version} <= $me->{ringver};	# we already have current version

    my @ring;
    for my $p ( @{$res->{data}{part}} ){
        push @ring, $p;
    }

    @ring = sort { $a->{shard} <=> $b->{shard} } @ring;
    $me->{ring} = \@ring;
    $me->{ringver} = $res->{data}{version};

}

sub _shard {
    my $me  = shift;
    my $key = shift;

    return unpack( 'N', md5($key) );
}

sub _servers_for_key {
    my $me  = shift;
    my $key = shift;

    # not sharded? all servers
    if( ! $me->{ring} ){
        my @s;

        @s = @{ $me->{mapservers} } if $me->{mapservers};
        @s = @{ $me->{allservers} } unless @s;

        shuffle(\@s);
        return \@s;
    }

    my $shard = $me->_shard($key);

    my $part;
    for my $r (@{$me->{ring}}){
        next if $shard > $r->{shard};
        $part = $r;
    }
    $part ||= $me->{ring}[0];
    print STDERR "shard $shard ", dumper($part), "\n";

    my @s = map {
        $me->{servers}{$_} ? ($me->{servers}{$_}) : ()
    } @{$part->{server}};

    return \@s if @s;
    return $me->{mapservers} if $me->{mapservers};
    return $me->{allservers};
}

################################################################

sub _send_request {
    my $me   = shift;
    my $serv = shift;	# list
    my $req  = shift;
    my $file = shift;	# reference

    my $tries = $me->{retries} + 1;
    my $copy  = $me->{copies} || 1;
    my $delay = 0.25;

    $tries = $copy if $tries < $copy;

    my $s = shift @$serv;

    for (1 .. $tries){
        return unless $s;
        my $res = $me->_try_server($s->{addr}, $s->{port}, $req, $file);
        return $res if $res && !--$copy;
        $s = shift @$serv;
        sleep $delay;
        $delay *= 1.414;
    }
}

sub _try_server {
    my $me   = shift;
    my $addr = shift;
    my $port = shift;
    my $req  = shift;
    my $file = shift;	# reference

    my $ipn = inet_aton($addr);
    $req .= $$file if $file;

    $me->{debug}->("trying to contact fbdb server $addr:$port");
    my $res;
    eval {
        $res = $me->{proto}->send_request($ipn, $port, $req, $me->{debug}, $me->{timeout});
        $res->{data} = $me->{proto}->decode_reply( $res ) if $res;
    };
    if(my $e = $@){
        $me->{debug}->("fbdb request failed: $e");
        $res = undef;
    }
    return $res;
}


################################################################

sub _getset {
    my $me  = shift;
    my $key = shift;
    my $req = shift;

    my $now = time();

    # get servers?
    # get ring?

    if( $me->{servertime} < $now - $OLDAGE ){
        $me->_read_server_list();
        die "no FBDB servers available\n" unless $me->{allservers} && @{$me->{allservers}};
    }

    if( $me->{ringtime} < $now - $OLDAGE ){
        $me->_read_ringcf();
    }

    my $serv = $me->_servers_for_key( $key );
    my $res  = $me->_send_request($serv, $req, undef);

    # mark ringcf as out-of-date, if we see it changed
    if( $res && $res->{data} && $res->{data}{data} ){
        $me->{ringtime} = 0 if $res->{data}{data}{conf_time} && $me->{ringver} != $res->{data}{data}{conf_time};
    }

    return $res;
}

sub get {
    my $me  = shift;
    my $key = shift;
    my $ver = shift;

    my $req = $me->{proto}->encode_request( {
        type		=> 'y2db_get',
        msgidno		=> rand(0xFFFFFFFF),
        want_reply	=> 1,
    }, {
        data	=> [ {
            map		=> $me->{map},
            key		=> $key,
            version	=> $ver,
        } ]
    } );

    return $me->_getset($key, $req);
}

sub distribute {
    my $me   = shift;
    my $key  = shift;
    my $ver  = shift;
    my $val  = shift;
    my $prog = shift;	# [ jsfunc, arg, arg, ... ]

    return unless $key && $ver;
    $me->{retries} = 25 unless $me->{retries};

    my $req = $me->{proto}->encode_request( {
        type		=> 'y2db_distrib',
        msgidno		=> rand(0xFFFFFFFF),
        want_reply	=> 1,
    }, {
        sender		=> "$HOSTNAME/$$",
        hop		=> 0,
        expire		=> time() + 120,
        data	=> [ {
            map		=> $me->{map},
            key		=> $key,
            version	=> $ver,
            value	=> $val,
            program	=> $prog,
        } ]
    } );


    return $me->_getset($key, $req);
}


################################################################

1;
