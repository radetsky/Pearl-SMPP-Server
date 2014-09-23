Pearl-SMPP-Server
=================

New generation of my SMPP Servers based on AnyEvent. Not Net::SMPP anymore!  

Pearl::SMPP::Server is a constructor-parent-skeleton for your future SMPP-server.  
It has basic logic of application SMSC corresponding to SMPP v.3.4.  

You can use this class but this is not simple. You must specify next callbacks:
- authentication
- аuthorization
- handler to submit 
- handler to get messages to deliver 
- handler to deliver sm response 
- handler to disconnect 

SYNOPSIS

  my $server = Pearl::SMPP::Server->new (  
    debug => $debug, 
    host => $conf->{'host'},
    port => $conf->{'port'},
    on_bound => sub { 
      my ($fh, $host, $port) = @_; 
      $logger->debug("Bound to $host:$port\n") if $debug;  
    }, 

    system_id => $conf->{'system_id'}, 

    authentication => sub { 
      my ( $login, $password, $host, $port ) = @_;
      return authentication ( $login, $password, $host, $port ); 
    },

    authorization => sub { 
      my ( $host, $port, $source_address ) = @_; 
      return authorization ($host, $port, $source_address);    # return undef if disabled to use $source with $id 
    }, 

    submit_sm  =>  sub { 
      my ( $host, $port, $pdu ) = @_; 
      return handle_submit_sm ($host, $port, $pdu ); # return undef if fail  , return message_id if Ok; 
    }, 

    outbound_q => sub { 
      $logger->debug("Timer") if $debug;  
      return handle_outbound ();       
    },

    handle_deliver_sm_resp => sub { 
      my ($host, $port, $pdu) = @_; 
      return handle_deliver_sm_resp ($host, $port, $pdu); #return undef always 
    }, 

    disconnect => sub { 
      my ($host, $port) = @_; 
      delete $connections->{connection_id($host,$port)};
      $logger->info("Disconnect from $host:$port");
    }

    ); 

  AnyEvent->condvar->recv; 


