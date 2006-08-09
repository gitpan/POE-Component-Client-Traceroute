package POE::Component::Client::Traceroute;

use warnings;
use strict;

use Exporter;
use vars qw(@ISA @EXPORT_OK %EXPORT_TAGS);

@ISA = qw(Exporter);
@EXPORT_OK = qw( );
%EXPORT_TAGS = ( );

use vars qw($VERSION $debug $debug_socket);

$VERSION    = '0.10';

use Carp qw(croak);
use Socket;
use FileHandle;
use Net::RawIP;
use Time::HiRes qw(time);

use POE::Session;
use POE::Kernel;

$debug         = 0;
$debug_socket  = 0;

sub DEBUG         () { $debug } # Enable debug output.
sub DEBUG_SOCKET  () { $debug_socket } # Output socket information.

# from asm/socket.h
sub SO_BINDTODEVICE () { 25 }

# from netinet/in.h
sub IPPROTO_IP () { 0 }

# from bits/in.h
sub IP_TTL     () { 2 }

# Length of IP headers
sub IP_HEADERS () { 28 }

# Spawn a new PoCo::Client::Traceroute session. This is the basic
# constructor, but it does not return an object. Instead it launches
# a new POE session.

sub spawn
{
   my $type = shift;

   croak "$type->spawn() requires an even number of parameters\n" if (@_ % 2);
   my %params;

   # Force parameters to lower case to be nice to users
   for (my $i=0; $i<@_; $i+=2)
   {
      $params{lc($_[$i])} = $_[$i+1];
   }

   my $alias      = delete $params{alias} || "tracer";
   my $firsthop   = delete $params{firsthop} || 1;
   my $maxttl     = delete $params{maxttl} || 32;
   my $timeout    = delete $params{timeout} || undef;
   my $qtimeout   = delete $params{querytimeout} || 3;
   my $queries    = delete $params{queries} || 3;
   my $baseport   = delete $params{baseport} || 33434;
   my $packetlen  = delete $params{packetlen} || 40;
   my $srcaddr    = delete $params{sourceaddress} || undef;
   my $device     = delete $params{device} || undef;
   my $perhop     = delete $params{perhoppostback} || 0;
   my $useicmp    = delete $params{useicmp} || 0;

   $debug         = delete $params{debug} || $debug;
   $debug_socket  = delete $params{debugsocket} || $debug_socket;
   
   croak(
      "$type doesn't know these parameters: ", join(', ', sort keys %params)
   ) if %params;

   croak(
      "FirstHop must be less than 255"
   ) if ($firsthop > 255);
   
   croak(
      "MaxTTL must be less than 255"
   ) if ($maxttl > 255);

   croak(
      "PacketLen must be less than 1492 and greater than 31"
   ) if ($packetlen > 1492 or $packetlen < 32);

   if ($useicmp)
   {
      croak "UseICMP option not yet implemented\n";
   }

   POE::Session->create(
      inline_states => {
         _start            => \&tracer_start,
         traceroute        => \&tracer_traceroute,
         shutdown          => \&tracer_shutdown,
         _start_traceroute => \&_start_traceroute,
         _send_packet      => \&_send_packet,
         _recv_packet      => \&_recv_packet,
         _timeout          => \&_timeout,
         _default          => \&tracer_default,
      },
      args => [
         $alias, $firsthop, $maxttl, $timeout, $qtimeout, $queries,
         $baseport, $packetlen, $srcaddr, $perhop, $useicmp, $device,
      ],
   );

   undef;
}

# Startup initialization method. Sets defaults from the spawn method
# and ties the alias to the session.
sub tracer_start
{
   my (
      $kernel, $heap,
      $alias, $firsthop, $maxttl, $timeout, $qtimeout, $queries,
      $baseport, $packetlen, $srcaddr, $perhop, $useicmp, $device,
   ) = @_[ KERNEL, HEAP, ARG0..$#_ ];

   DEBUG and warn "PoCo::Client::Traceroute session $alias started\n";

   $heap->{defaults} = {
         firsthop       => $firsthop,
         maxttl         => $maxttl,
         timeout        => $timeout,
         queries        => $queries,
         querytimeout   => $qtimeout,
         baseport       => $baseport,
         packetlen      => $packetlen,
         perhoppostback => $perhop,
         useicmp        => $useicmp,
         sourceaddress  => $srcaddr,
         device         => $device,
   };

   my $proto   = getprotobyname('icmp');
   my $socket  = FileHandle->new();
   
   socket($socket, PF_INET, SOCK_RAW, $proto) || 
      croak("ICMP Socket error - $!");
   
   DEBUG_SOCKET and warn "TRS: Created ICMP socket to receive errors\n";
   $heap->{icmpsocket} = $socket;

   $kernel->select_read($socket, '_recv_packet', 0);

   $heap->{alias}       = $alias;
   $kernel->alias_set($alias);
}

# The traceroute state takes 2 required and one optional argument. The first
# is the event to post back to the sender, the second is the host to traceroute
# to, the last is an array ref with options to override the defaults.
sub tracer_traceroute
{
   my ($kernel, $heap, $sender, $event, $host, $useroptions) = 
      @_[ KERNEL, HEAP, SENDER, ARG0..ARG2 ];

   unless ($event)
   {
      if (DEBUG) { die "Postback state name required for traceroute\n" }
      return;
   }

   DEBUG and warn "TR: Starting traceroute to $host\n" if ($host);

   my $error = "Host required for traceroute\n" unless ($host);

   my %options = %{$heap->{defaults}};
   my $callback;

# Allow user to override options for each traceroute request
   if (ref $useroptions eq "ARRAY")
   {
      my @useropts = @$useroptions;
      $error = "traceroute useroptions requires an even number of parameters\n" 
         if (@useropts % 2);
      my %uparams;

      for (my $i=0; $i<@useropts; $i+=2)
      {
         $uparams{lc($useropts[$i])} = $useropts[$i+1];
      }

      $callback = delete $uparams{callback};

      foreach my $option (keys %options)
      {
         $options{$option} = delete $uparams{$option} 
            if (exists $uparams{$option});
      }
      
      $error .= "traceroute doesn't know these parameters: " . 
         join(', ', sort keys %uparams) . "\n" if %uparams;
   }
   elsif (defined $useroptions)
   {
      $error .= "traceroute's third argument must be an array ref\n";
   }

   if ($options{useicmp})
   {
      $error .= "UseICMP option not yet implemented\n";
   }

   if ($options{baseport} > 65279)
   {
      $error .= "Baseport is too high, must be less than 65280\n";
   }

   if ($options{maxttl} > 255)
   {
      $error .= "MaxTTL can not be higher than 255\n";
   }

   if ($options{firsthop} > 255)
   {
      $error .= "FirstHop can not be higher than 255\n";
   }

   if ($options{firsthop} > $options{maxttl})
   {
      $error .= "FirstHop must be less than or equal to MaxTTL\n";
   }

   if ($options{packetlen} > 1492 or $options{packetlen} < 32)
   {
      $error .= "PacketLen must be less than 1492 and greater than 31\n";
   }

   my $postback = $sender->postback( $event, $host, \%options, $callback );

   if ($error)
   {
      DEBUG and warn "Errors starting traceroute\n";
      $postback->( _build_postback_options(undef, $error) );
   }
   else
   {
      my $trsessionid = ++$heap->{trsessionid};

      $heap->{sessions}{$trsessionid}{postback}    = $postback;
      $heap->{sessions}{$trsessionid}{options}     = \%options;
      $heap->{sessions}{$trsessionid}{host}        = $host;

      if ($options{perhoppostback})
      {
         $heap->{sessions}{$trsessionid}{callback} = $callback;
         $heap->{sessions}{$trsessionid}{sender}   = $sender;
      }

      if ($options{timeout})
      {
         my $alarm = 
            $kernel->delay_set('_timeout',$options{timeout},$trsessionid,1);

         $heap->{sessions}{$trsessionid}{timeout} = $alarm;
      }

      $kernel->yield('_start_traceroute' => $trsessionid);
   }
}

sub tracer_shutdown
{
   my ($kernel, $heap) = @_[ KERNEL, HEAP ];
   DEBUG and warn "PoCo::Client::Traceroute session " . $heap->{alias} .
      " shutting down\n";

   $kernel->select_read($heap->{icmpsocket});
   $kernel->alarm_remove_all();

   $kernel->alias_remove($heap->{alias});
}

# The following state functions are private, for internal use only.

sub _start_traceroute
{
   my ($kernel,$heap,$trsessionid) = @_[ KERNEL, HEAP, ARG0 ];
   my $session = $heap->{sessions}{$trsessionid};

   DEBUG and warn "TR: Starting traceroute session $trsessionid\n";

   my $proto   = getprotobyname('udp');
   my $socket  = FileHandle->new();
   
   socket($socket, PF_INET, SOCK_DGRAM, $proto) || 
      croak("UDP Socket error - $!");
   
   DEBUG_SOCKET and warn "TRS: Created socket $socket\n";

   if ($session->{options}{device})
   {
      my $device = $session->{options}{device};
      setsockopt($socket, SOL_SOCKET, SO_BINDTODEVICE(), pack("Z*", $device)) 
         or croak "error binding to device $device - $!";

      DEBUG_SOCKET and warn "TRS: Bound socket to $device\n";
   }

   if (  $session->{options}{sourceaddress} and 
         $session->{options}{sourceaddress} ne "0.0.0.0" )
   {
      _bind($socket, $session->{options}{sourceaddress});
   }


   my $destination = inet_aton($session->{host});
   if (not defined $destination)
   {
      $session->{postback}->(
            _build_postback_options(undef,"Could not resolve $destination\n")
      );
   }
   else
   {
      $session->{destination}    = $destination;
      $session->{socket_handle}  = $socket;
      $kernel->select_read($socket, '_recv_packet', $trsessionid, 'xyz');

                           
      $kernel->yield( "_send_packet" => $trsessionid );
   }
}

sub _send_packet
{
   my ($kernel, $heap, $trsessionid) = @_[ KERNEL, HEAP, ARG0 ];
   my $session = $heap->{sessions}{$trsessionid};

   if (not exists $session->{hop})
   {
      $session->{hop} = $session->{options}{firsthop};
   }

   my $hop           = $session->{hop};
   my $port          = $session->{options}{baseport} + $hop - 1;

   my $currentquery  = scalar keys %{$session->{hops}{$hop}};

   my $message       = "a" x ($session->{options}{packetlen} - IP_HEADERS);
   
   if (not exists $session->{lastport} or $session->{lastport} != $port)
   {
      my $socket_addr   = sockaddr_in($port,$session->{destination});
      connect($session->{socket_handle},$socket_addr);
      DEBUG_SOCKET and warn "TRS: Connected to $session->{host}\n";

      setsockopt($session->{socket_handle}, IPPROTO_IP, IP_TTL, pack('C',$hop));
      DEBUG_SOCKET and warn "TRS: Set TTL to $hop\n";

      my $localaddr           = getsockname($session->{socket_handle});
      my ($port,$addr)        = sockaddr_in($localaddr);
      $session->{localport}   = $port;
      $heap->{ports}{$port}   = $trsessionid;
   }

   $session->{lasttime} = time;
   my $alarm            = $kernel->delay_set('_timeout', 
         $session->{options}{querytimeout}, $trsessionid, 0);

   $session->{alarm}    = $alarm;

   DEBUG and warn "TR: Sent packet for $trsessionid\n";
   send($session->{socket_handle}, $message, 0);
   
}

sub _recv_packet
{
   my ($kernel, $heap, $socket, $trsessionid) = @_[ KERNEL, HEAP, ARG0, ARG2 ];
   my ($recv_msg, $from_saddr, $from_port, $from_ip, $destunreach);

   my $replytime = time;

   $from_saddr             = recv($socket, $recv_msg, 1500, 0);
   
   if (defined $from_saddr)
   {
      ($from_port,$from_ip)   = sockaddr_in($from_saddr);
      $from_ip                = inet_ntoa($from_ip);
      DEBUG and warn "TR: Received packet from $from_ip\n";
   }

   if (defined $trsessionid and $trsessionid == 0)
   {
      DEBUG and warn "TR: Received ICMP packet\n";

      my $icmp = new Net::RawIP({icmp=>{}});
      my $udp  = new Net::RawIP({udp=>{}});

      $icmp->bset($recv_msg);
      my ($icmp_ip,$type,$code,$icmp_data) = 
         $icmp->get({ip=>['daddr'],icmp=>['type','code','data']});

      $from_ip = inet_ntoa(pack('N',$icmp_ip)) unless ($from_ip);

      if ($type == 11 or $type == 3)
      {
         $udp->bset($icmp_data);
         my ($reply_sport) = $udp->get({udp=>['source']});

         $trsessionid   = $heap->{ports}{$reply_sport};
         $destunreach   = ($type == 3) ? 1 : 0;
      }
   }

   if ($trsessionid and $from_ip)
   {
      my $session = $heap->{sessions}{$trsessionid};
      DEBUG and warn "TR: Received packet for $trsessionid\n";

      $kernel->alarm_remove($session->{alarm});

      my $hop           = $session->{hop};
      my $currentquery  = scalar keys %{$session->{hops}{$hop}};

      $session->{hops}{$hop}{$currentquery} = {
            remoteip    => $from_ip,
            replytime   => $replytime - $session->{lasttime},
      };

      $session->{stop} = 1 if ($destunreach);

      my $continue = _process_results($session,$currentquery);

      if ($continue)
      {
         $kernel->yield('_send_packet',$trsessionid);
      }
      else
      {
         $kernel->select_read($session->{socket_handle});
         $kernel->alarm_remove($session->{timeout});
         delete $heap->{sessions}{$trsessionid};
      }
   }
}

sub _timeout
{
   my ($kernel,$heap,$trsessionid,$stop) = @_[ KERNEL,HEAP,ARG0,ARG1 ];
   my $session = $heap->{sessions}{$trsessionid};

   return unless $session;

   if ($stop)
   {
      my $error = "Traceroute session timeout\n";

      $session->{postback}->(_build_postback_options($session,$error));
      $kernel->select_read($session->{socket_handle});
      $kernel->alarm_remove($session->{timeout});
      delete $heap->{sessions}{$trsessionid};
      return;
   }

   my $hop           = $session->{hop};
   my $currentquery  = scalar keys %{$session->{hops}{$hop}};

   $session->{hops}{$hop}{$currentquery} = {
         remoteip    => '',
         replytime   => '*',
   };

   DEBUG and warn "TR: Timeout on $hop ($currentquery) for $trsessionid\n";

   my $continue = _process_results($session,$currentquery);
   if ($continue)
   {
      $kernel->yield('_send_packet',$trsessionid);
   }
   else
   {
      $kernel->select_read($session->{socket_handle});
      $kernel->alarm_remove($session->{timeout});
      delete $heap->{sessions}{$trsessionid};
   }
}

sub tracer_default
{
   DEBUG and warn "Unknown state: " . $_[ARG0] . "\n";
}

# Internal private functions

sub _bind
{
   my ($socket, $sourceaddress) = @_;

   my $ip = inet_aton($sourceaddress);
   croak("TR: nonexistant local address $sourceaddress") unless (defined $ip);

   CORE::bind($socket, sockaddr_in(0,$ip)) ||
      croak("TR: bind error - $!\n");

   DEBUG_SOCKET and warn "TRS: Bound socket to $sourceaddress\n";

   return 1;
}

sub _process_results
{
   my ($session,$currentquery) = @_;

   if ($currentquery + 1 == $session->{options}{queries})
   {
      if ($session->{options}{perhoppostback})
      {
         my $postback = $session->{sender}->postback(
               $session->{options}{perhoppostback},
               $session->{host},
               $session->{options},
               $session->{callback}
         );

         my $hop  = $session->{hop};
         my @rows = _build_hopdata($session->{hops}{$hop}, $hop);

         $postback->( $hop, \@rows, undef ); # No error
      }

      $session->{hop}++;
      if ($session->{hop} > $session->{options}{maxttl} or $session->{stop})
      {
         my $error = ($session->{stop}) ? 
            undef : "MaxTTL exceeded without reaching target";

         $session->{postback}->(_build_postback_options($session,$error));
         return 0;
      }
   }

   return 1;
}

sub _build_postback_options
{
   my ($session,$error) = @_;

   my $hops    = 0;
   my @hopdata = ();
   
   if (defined $session)
   {
      foreach my $hop (sort {$a <=> $b} keys %{$session->{hops}})
      {
         my @rows = _build_hopdata($session->{hops}{$hop},$hop);
         $hops = $hop if $rows[0]->{routerip};

         push (@hopdata,@rows);
      }
   }

   my @response = ( $hops, \@hopdata, $error );
   return @response;
}

sub _build_hopdata
{
   my ($hopref,$hop) = @_;

   my @hopdata       = ();
   my %row           = ();
   $row{hop}         = $hop;
   
   my @results       = ();
   foreach my $query (sort {$a <=> $b} keys %{$hopref})
   {
      my $routerip   = $hopref->{$query}{remoteip};
      my $replytime  = $hopref->{$query}{replytime};

      push (@results, $replytime);
      if (exists $row{routerip} and 
            $row{routerip} ne $routerip and
            $routerip ne "" )
      {
         DEBUG and warn "TR: Router IP changed during hop $hop from " .
            $row{routerip} . " to $routerip\n";

         $row{results} = \@results;
         push (@hopdata,\%row);
         undef %row;
         undef @results;
         $row{hop} = $hop;
      }

      $row{routerip} = $routerip unless defined $row{routerip};
   }

   $row{results} = \@results;
   push (@hopdata,\%row);

   return @hopdata;
}

1;

__END__

=head1 NAME

POE::Component::Client::Traceroute - a non-blocking traceroute client

=head1 SYNOPSIS

  use POE qw(Component::Client::Traceroute);

  POE::Component::Client::Traceroute->spawn(
    Alias          => 'tracer',   # Defaults to tracer
    FirstHop       => 1,          # Defaults to 1
    MaxTTL         => 16,         # Defaults to 32 hops
    Timeout        => 0,          # Defaults to never
    QueryTimeout   => 3,          # Defaults to 3 seconds
    Queries        => 3,          # Defaults to 3 queries per hop
    BasePort       => 33434,      # Defaults to 33434
    PacketLen      => 128,        # Defaults to 40
    SourceAddress  => '0.0.0.0',  # Defaults to '0.0.0.0'
    PerHopPostback => 0,          # Defaults to no PerHopPostback
    Device         => 'eth0',     # Defaults to undef
    UseICMP        => 0,          # Defaults to 0, NOTE: Not implemented!
    Debug          => 0,          # Defaults to 0
    DebugSocket    => 0,          # Defaults to 0
  );

  sub some_event_handler 
  {
    $kernel->post(
        "tracer",           # Post request to 'tracer' component
        "traceroute",       # Ask it to traceroute to an address
        "trace_response",   # Post answers to 'trace_response'
        $destination,       # This is the host to traceroute to
        [
          Queries   => 5,         # Override the global queries parameter
          MaxTTL    => 30,        # Override the global MaxTTL parameter
          Callback  => [ $args ], # Data to send back with postback event
        ]
    );
  }

  # This is the sub which is called with the responses from the
  # Traceroute component.
  sub trace_response
  {
    my ($request,$response) = @_[ARG0, ARG1];

    my ($destination, $options, $callback) = @$request;
    my ($hops, $data, $error)              = @$response;

    if ($hops)
    {
      print "Traceroute results for $destination\n";

      foreach my $hop (@$data)
      {
        my $hopnumber = $hop->{hop};
        my $routerip  = $hop->{routerip};
        my @rtts      = @{$hop->{results}};

        print "$hopnumber\t$routerip\t";
        foreach (@rtts)
        {
          if ($_ eq "*") { print "* "; }
          else { printf "%0.3fms ", $_*1000; }
        }
        print "\n";
      }
    }

    warn "Error occurred tracing to $destination: $error\n" if ($error);
  }

  or
  
  sub another_event_handler 
  {
    $kernel->post(
        "tracer",           # Post request to 'tracer' component
        "traceroute",       # Ask it to traceroute to an address
        "trace_response",   # Post answers to 'trace_response'
        $destination,       # This is the host to traceroute to
        [
          # The trace_row event will get called after each hop
          PerHopPostback  => 'trace_row', 
        ]
    );
  }

  sub trace_row
  {
    my ($request,$response) = @_[ARG0, ARG1];

    my ($destination, $options, $callback) = @$request;
    my ($currenthop, $data, $error)        = @$response;

    # $data only contains responses for the current TTL
    # The structure is the same as for trace_response above
  }

=head1 DESCRIPTION

POE::Component::Client::Traceroute is a non-blocking Traceroute client.
It lets several other sessions traceroute through it in parallel, and it lets
them continue doing other things while they wait for responses.

Traceroute client components are not proper objects. Instead of being created, 
as most objects are, they are "spawned" as separate sessions. To avoid 
confusion, and to remain similar to other POE::Component modules, they must
be spawned with the C<spawn> method, not created with a C<new> one.

Furthermore, there should never be more than on PoCo::Client:Traceroute session
spawned within an application at the same time. Doing so may cause unexpected
results.

PoCo::Client::Traceroute's C<spawn> method takes a few named parameters, all
parameters can be overridden for each call to the 'traceroute' event unless
otherwise stated.

=over 2

=item Alias => $session_alias

C<Alias> sets the component's alias. It is the target of post() calls.
Alias defaults to 'tracer'. Alias can not be overridden.

=item FirstHop => $firsthop

C<FirstHop> sets the starting TTL value for the traceroute. FirstHop defaults
to 1 and can not be set higher than 255 or greater than C<MaxTTL>.

=item MaxTTL => $maxttl

C<MaxTTL> sets the maximum TTL for the traceroute. Once this many hops have
been attempted, if the target has still not been reached, the traceroute
finishes and a 'MaxTTL exceeded without reaching target' error is returned
along with all of the data collected. MaxTTL defaults to 32 and can not be
set higher than 255.

=item Timeout => $timeout

C<Timeout> sets the maximum time any given traceroute will run. After this
time the traceroute will stop in the middle of where ever it is and a 
'Traceroute session timeout' error is returned along with all of the data 
collected. Timeout defaults to 0, which disables it completely.

=item QueryTimeout => $qtimeout

C<QueryTimeout> sets the maximum before an individual query times out. If
the query times out an * is set for the response time and the router IP 
address in the results data. QueryTimeout defaults to 3 seconds.

=item Queries => $queries

C<Queries> sets the number of queries for each hop to send. The response time
for each query is recorded in the results table. The higher this is, the
better the chance of getting a response from a flaky device, but the longer
a traceroute takes to run. Queries defaults to 3.

=item BasePort => $baseport

C<BasePort> sets the first port used for traceroute when not using ICMP.
The BasePort is incremented by one for each hop, by traceroute convention.
BasePort defaults to 33434 and can not be higher than 65279.

=item PacketLen => $packetlen

C<PacketLen> sets the length of the packet to this many bytes. PacketLen
defaults to 40 and can not be less than 32 or greater than 1492.

=item SourceAddress => $sourceaddress

C<SourceAddress> is the address that the socket binds to. It must be an IP
local to the system or the component will die. If set to '0.0.0.0', the 
default, it picks the first IP on the device which routes to the destination.

=item Device => $device

C<Device> is the device to bind the socket to. It defaults to the interface
which routes to the destination. The component will die if the device does
not exist or is shut down.

=item PerHopPostback => $event

C<PerHopPostback> turns on per hop postbacks within the component. The 
postback is sent to the event specified in the caller's session. By
default there is no PerHopPostback.

=item UseICMP => $useicmp

C<UseICMP> is not yet implemented and the interface to it may change. Setting
this option will cause the component to die.

=item Debug => $debug

C<Debug> enables verbose debugging output. Debug defaults to 0.

=item DebugSocket => $debug_sock

C<DebugSocket> enables verbose debugging on socket activity. DebugSocket
defaults to 0.

=back

Sessions communicate asynchronously with the Client::Traceroute component.
The post traceroute requests to it, and the receive events back upon 
completion. The optionally receive events after each hop.

Requests are posted to the components 'traceroute' handler. The include
the name of an event to post back, an address to traceroute to, and optionally
parameters to override from the default and callback arguments. The address
may be a numeric dotted quad, a packed inet_aton address, or a host name.

Traceroute responses come with two array references:

  my ($request, $response) = @_[ ARG0, ARG1 ];

C<$request> contains information about the request:

  my ($destination, $options, $callback) = @$request;

=over 2

=item C<$destination>

This is the original request traceroute destination. It matches the address
posted to the 'traceroute' event.

=item C<$options>

This is a hash reference with all the options used in the traceroute, both
the defaults and the overrides sent with the request.

=item C<$callback>

This is the callback arguments passed with the original request.

=back

C<$response> contains information about the traceroute response. It is 
different depending on if the the event was a postback or a PerHopPostback.

Postback array:

  my ($hops, $data, $error) = @$response;

PerHopPostback array:

  my ($currenthop, $data, $error) = @$response;

=over 2

=item C<$hops>

This is the largest hop with a response. It may be less than MaxTTL.

=item C<$currenthop>

This is the current hop that the data is posted for. It changes with each
call to the PerHopPostback event.

=item C<$data>

This is an array of hash references. For the Postback event, it contains at
least one row for each TTL between FirstHop and the device or MaxTTL. For
PerHopPostback events it contains at least one row for the current TTL hop.

A single TTL hop may have more than one row if the IP address changed during
polling.

The structure of the array ref is the following:

  $data->{routerip} = $routerip;
  $data->{hop}      = $currenthop;
  $data->{results}  = \@trip_times;

=over 2

=item C<$data-E<gt>{routerip}>

This is the router IP which responded with the TTL expired in transit or
destination unreachable message. If it changes a new row is generated. If
all queries for this hop timed out, this will be set to an empty string.

=item C<$data-E<gt>{hop}>

This is the current hop that the result set is for. It is incremented by one
for each TTL between FirstHop and reaching the device or MaxTTL.

=item C<$data-E<gt>{results}>

This is an array ref containing the result round trip times for each query
in seconds to millisecond precision depending on the system. If a query packet
timed out the entry in the array will be set to "*".

=back

=back

=head1 SEE ALSO

This component's Traceroute code was heavily influenced by 
Net::Traceroute::PurePerl and Net::Ping.

See POE for documentation on how POE works.

Also see the test program, t/01_trace.t, in the distribution.

=head1 BUGS

UseICMP currently errors out if set. This module was only tested on recent
Linux platforms and may not work elsewhere.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::Traceroute is Copyright 2006 by Andrew Hoying.
All rights reserved. POE::Component::Client::Traceroute is free software; you
may redistribute it and or modify it under the same terms as Perl itself.

Andrew my be contacted by e-mail via <ahoying@cpan.org>.

You can learn more about POE at <http://poe.perl.org/>.

=cut

