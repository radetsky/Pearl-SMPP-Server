  #!/usr/bin/perl 

  use 5.8.0; 
	use strict; 
	use warnings; 

	use lib '../Pearl-SMPP-Server'; 
  use lib '../SMPP-Packet/lib'; 

	use Pearl::SMPP::Server;
  use AnyEvent; 
  use Data::Dumper; 
  
  my $server = Pearl::SMPP::Server->new (  
    debug => 1, 
    host => '127.0.0.1',
    port => 9900,
    system_id => 'AnyEvent', 
    authentication => sub { 
      my ( $system_id, $secret, $host, $port ) = @_;
      my $id = $host . ":" . $port; 
      return $id;  # return undef if fail
    },

    authorization => sub { 
      my ( $id, $source ) = @_; 
      return 1;    # return undef if disabled to use $source with $id 
    }, 

    rps => sub { 
      my ( $id, $rps ) = @_; 
      return 1;     # return undef if throttled 
    }, 

    submit_sm  =>  sub { 
      my ( $system_id, $pdu ) = @_; 
      warn "We received the PDU submit_sm:"; 
      warn Dumper $pdu; 
      return 12345678;     # return undef if fail  , return message_id if Ok; 
    }, 

    outbound_q => sub { 
      my ( $system_id ) = @_; 
      return ( SMPP::Packet::pack_pdu ( { 
          source_address => 'A-name', 
          version => 0x34, 
          short_message => 'Short message already encoded text', 
          destination_addr => '380504139380'
        }))
    }
    ); 

 AnyEvent->condvar->recv; 

