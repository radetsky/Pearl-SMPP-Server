#===============================================================================
#
#         FILE:  Server.pm
#
#  DESCRIPTION:  Pearl::SMPP::Server - Асинхроннный AnyEvent::PacketReader based 
#  				 сервер. С человеческой логикой, но внешними инструментами на проверку логина, 
#				 посылку сообщения и прием сообщения из очереди.  
#
#        NOTES:  ---
#       AUTHOR:  Alex Radetsky (Rad), <rad@rad.kiev.ua>
#      COMPANY:  PearlPBX
#      VERSION:  1.0
#      CREATED:  19.07.2014 17:13:03 EEST
#===============================================================================
=head1 NAME

Pearl::SMPP::Server 

=head1 SYNOPSIS

  use Pearl::SMPP::Server 
  
  my $server = Pearl::SMPP::Server->new ( { 
	host => undef, 
	port => 9900, 
    authentication => sub { 
      my ( $system_id, $secret, $host, $port ) = @_;
      my $user = {
          system_id => $system_id, 
          bandwidth => 10, 
          active = 1, 
          allowed_ip = '0.0.0.0',
          allowed_src= 'test,alpha,beta',
          max_connections = 10
      }
      return $user;   # return undef if fail
    },

    authorization => sub { 
      my ( $system_id, $source ) = @_; 
      return 1;    # return undef if disabled to use $source with $id 
    }, 

    rps => sub { 
      my ( $id, $rps ) = @_; 
      return 1;     # return undef if throttled 
    }, 

    received_sm  =>  sub { 
      my ( $id, $received_sm ) = @_; 
      return 1;     # return undef if fail  
    }, 

    outbound_q => sub { 
      my ( $system_id ) = @_; 
      return Pearl::SMPP::PDU->new( { 
      		from => 'A', 
      		to => 'B', 
      		type => 'DLR', 
      		text => 'DLR Text'
      	}); 
      }
    } 
    ); 

=head1 DESCRIPTION

Pearl SMPP Server - это асинхронный сервер, построенный на базе AnyEvent tcp_server + PacketReader. 
Используемые callback-и, которые должен обеспечить внешний разработчик: 
1. authentication - аутентификация. Входящие параметры: host, port, system_id, secret.  
Должен возвращать hashref-> с записями о пользователе, если ОК, undef - если аутентификация не удалась. 
2. authorization - авторизация. Проверка на возможность использовании А-имени $source пользователем $system_id

3. rps - пока не используется 
4. outbound_q - вызывается по timeout в 1 сек.  Проверка исходящей очереди для $system_id. В качестве результата должна 
возвращать массив Pearl::SMPP::PDU.  

TODO: 
- Установить AnyEvent какой-нибудь таймер на 1 секунду для проверки наличия исходящих сообщений 
- Заюзать Unix-socket для передачи оперативной информации между процессами: 
 + оперативно сообщать о новых коннектах и пакетах 
 + сообщать о текущем статусе подключений и статистике с момента запуска 
 + принимать сообщения с командами
  - Reload config (?) нужен ли ? 
  + Kill $HIM when $HIM == system_id 
- проверять количество одновременных соединений.  
- проверять количество пакетов в секунду

=cut

package Pearl::SMPP::Server;

use lib '/User/rad/git/perl/SMPP-Packet/lib'; 

use 5.8.0;
use strict;
use warnings;

use AnyEvent; 
use AnyEvent::Socket qw/tcp_server/; 
use AnyEvent::PacketReader; 
use Data::Dumper; 
use Errno ':POSIX';
use SMPP::Packet; 
use Log::Log4perl qw(get_logger); 

#use Pearl::SMPP::PDU; 

use version; our $VERSION = "1.0";
our @EXPORT_OK = qw();

# SMPP PDU command_id table
use constant cmd_tab => {
  0x80000000 => 'generic_nack',
  0x00000001 => 'bind_receiver',
  0x80000001 => 'bind_receiver_resp',
  0x00000002 => 'bind_transmitter',
  0x80000002 => 'bind_transmitter_resp',
  0x00000003 => 'query_sm',
  0x80000003 => 'query_sm_resp',
  0x00000004 => 'submit_sm',
  0x80000004 => 'submit_sm_resp',
  0x80000005 => 'deliver_sm_resp',
  0x00000006 => 'unbind',
  0x80000006 => 'unbind_resp',
  0x00000007 => 'replace_sm',
  0x80000007 => 'replace_sm_resp',
  0x00000008 => 'cancel_sm',
  0x80000008 => 'cancel_sm_resp',
  0x00000009 => 'bind_transceiver',
  0x80000009 => 'bind_transceiver_resp',
  0x0000000b => 'outbind',
  0x00000015 => 'enquire_link',
  0x80000015 => 'enquire_link_resp',
};

### Command IDs, sec 5.1.2.1, table 5-1, pp. 110-111

use constant CMD_generic_nack          => 0x80000000;
use constant CMD_bind_receiver         => 0x00000001;
use constant CMD_bind_receiver_resp    => 0x80000001;
use constant CMD_bind_transmitter      => 0x00000002;
use constant CMD_bind_transmitter_resp => 0x80000002;
use constant CMD_query_sm              => 0x00000003;
use constant CMD_query_sm_resp         => 0x80000003;
use constant CMD_submit_sm             => 0x00000004;
use constant CMD_submit_sm_resp        => 0x80000004;
use constant CMD_deliver_sm            => 0x00000005;
use constant CMD_deliver_sm_resp       => 0x80000005;
use constant CMD_unbind                => 0x00000006;
use constant CMD_unbind_resp           => 0x80000006;
use constant CMD_replace_sm            => 0x00000007;
use constant CMD_replace_sm_resp       => 0x80000007;
use constant CMD_cancel_sm             => 0x00000008;
use constant CMD_cancel_sm_resp        => 0x80000008;
use constant CMD_bind_transceiver      => 0x00000009;  # v3.4
use constant CMD_bind_transceiver_resp => 0x80000009;  # v3.4
use constant CMD_delivery_receipt      => 0x00000009;  # v4     #4
use constant CMD_delivery_receipt_resp => 0x80000009;  # v4     #4
use constant CMD_enquire_link_v4       => 0x0000000a;  #4
use constant CMD_enquire_link_resp_v4  => 0x8000000a;  #4
use constant CMD_outbind               => 0x0000000b;
use constant CMD_enquire_link          => 0x00000015;
use constant CMD_enquire_link_resp     => 0x80000015;
use constant CMD_submit_multi          => 0x00000021;
use constant CMD_submit_multi_resp     => 0x80000021;
use constant CMD_alert_notification    => 0x00000102;
use constant CMD_data_sm               => 0x00000103;
use constant CMD_data_sm_resp          => 0x80000103;

use constant ESME_ROK         => 0x00000000; 
use constant ESME_RINVPASWD   => 0x0000000e; 
use constant ESME_RALYBND     => 0x00000005; 
use constant ESME_RSUBMITFAIL => 0x00000045;
use constant ESME_RINVSRCADR  => 0x0000000a;



use constant status_code => {
    0x00000000 => { code => 'ESME_ROK', msg => 'No error', },
    0x00000001 => { code => 'ESME_RINVMSGLEN', msg => 'Message Length is invalid', },
    0x00000002 => { code => 'ESME_RINVCMDLEN', msg => 'Command Length is invalid', },
    0x00000003 => { code => 'ESME_RINVCMDID',  msg => 'Invalid Command ID', },
    0x00000004 => { code => 'ESME_RINVBNDSTS', msg => 'Incorrect BIND Status for given command', },
    0x00000005 => { code => 'ESME_RALYBND',    msg => 'ESME Already in bound state', },
    0x00000006 => { code => 'ESME_RINVPRTFLG', msg => 'Invalid priority flag', },
    0x00000007 => { code => 'ESME_RINVREGDLVFLG', msg => 'Invalid registered delivery flag', },
    0x00000008 => { code => 'ESME_RSYSERR',    msg => 'System Error', },
#    0x00000009 => { code => 'ESME_', msg => '', },
    0x0000000a => { code => 'ESME_RINVSRCADR', msg => 'Invalid source address', },
    0x0000000b => { code => 'ESME_RINVDSTADR', msg => 'Invalid destination address', },
    0x0000000c => { code => 'ESME_RINVMSGID',  msg => 'Message ID is invalid', },
    0x0000000d => { code => 'ESME_RBINDFAIL',  msg => 'Bind failed', },
    0x0000000e => { code => 'ESME_RINVPASWD',  msg => 'Invalid password', },
    0x0000000f => { code => 'ESME_RINVSYSID',  msg => 'Invalid System ID', },
#   0x00000010 => { code => 'ESME_', msg => '', },
    0x00000011 => { code => 'ESME_RCANCELFAIL',  msg => 'Cancel SM Failed', },
#   0x00000012 => { code => 'ESME_', msg => '', },
    0x00000013 => { code => 'ESME_RREPLACEFAIL', msg => 'Replace SM Failed', },
    0x00000014 => { code => 'ESME_RMSGQFUL',     msg => 'Message queue full', },
    0x00000015 => { code => 'ESME_RINVSERTYP',   msg => 'Invalid service type', },
# 0x00000016 - 0x00000032 reserved
    0x00000033 => { code => 'ESME_RINVNUMDESTS', msg => 'Invalid number of destinations', },
    0x00000034 => { code => 'ESME_RINVDLNAME',   msg => 'Invalid distribution list name', },
# 0x00000035 - 0x0000003f reserved
    0x00000040 => { code => 'ESME_RINVDESTFLAG', msg => 'Destination flag is invalid (submit_multi)', },
#   0x00000041 => { code => 'ESME_', msg => '', },
    0x00000042 => { code => 'ESME_RINVSUBREP',   msg => "Invalid `submit with replace' request (i.e. submit_sm with replace_if_present_flag set)", },
    0x00000043 => { code => 'ESME_RINVESMCLASS', msg => 'Invalid esm_class field data', },
    0x00000044 => { code => 'ESME_RCNTSUBDL',    msg => 'Cannot submit to distribution list', },
    0x00000045 => { code => 'ESME_RSUBMITFAIL',  msg => 'submit_sm or submit_multi failed', },
#   0x00000046 => { code => 'ESME_', msg => '', },
#   0x00000047 => { code => 'ESME_', msg => '', },
    0x00000048 => { code => 'ESME_RINVSRCTON', msg => 'Invalid source address TON', },
    0x00000049 => { code => 'ESME_RINVSRCNPI', msg => 'Invalid source address NPI', },
# 0x0000004a - 0x0000004f undocumented
    0x00000050 => { code => 'ESME_RINVDSTTON', msg => 'Invalid destination address TON', },
    0x00000051 => { code => 'ESME_RINVDSTNPI', msg => 'Invalid destination address NPI', },
#   0x00000052 => { code => 'ESME_', msg => '', },
    0x00000053 => { code => 'ESME_RINVSYSTYP', msg => 'Invalid system_type field', },
    0x00000054 => { code => 'ESME_RINVREPFLAG', msg => 'Invalid replace_if_present flag', },
    0x00000055 => { code => 'ESME_RINVNUMMSGS', msg => 'Invalid number of messages', },
#   0x00000056 => { code => 'ESME_', msg => '', },
#   0x00000057 => { code => 'ESME_', msg => '', },
    0x00000058 => { code => 'ESME_RTHROTTLED', msg => 'Throttling error (ESME has exceeded allowed message limits)', },
# 0x00000059 - 0x00000060 reserved
    0x00000061 => { code => 'ESME_RINVSCHED', msg => 'Invalid scheduled delivery time', },
    0x00000062 => { code => 'ESME_RINVEXPIRY', msg => 'Invalid message validity period (expiry time)', },
    0x00000063 => { code => 'ESME_RINVDFTMSGID', msg => 'Predefined message invalid or not found', },
    0x00000064 => { code => 'ESME_RX_T_APPN', msg => 'ESME Receiver Temporary App Error Code', },
    0x00000065 => { code => 'ESME_RX_P_APPN', msg => 'ESME Receiver Permanent App Error Code', },
    0x00000066 => { code => 'ESME_RX_R_APPN', msg => 'ESME Receiver Reject Message Error Code', },
    0x00000067 => { code => 'ESME_RQUERYFAIL', msg => 'query_sm request failed', },
# 0x00000068 - 0x000000bf reserved
    0x000000c0 => { code => 'ESME_RINVOPTPARSTREAM', msg => 'Error in the optional part of the PDU Body', },
    0x000000c1 => { code => 'ESME_ROPTPARNOTALLWD', msg => 'Optional paramenter not allowed', },
    0x000000c2 => { code => 'ESME_RINVPARLEN', msg => 'Invalid parameter length', },
    0x000000c3 => { code => 'ESME_RMISSINGOPTPARAM', msg => 'Expected optional parameter missing', },
    0x000000c4 => { code => 'ESME_RINVOPTPARAMVAL', msg => 'Invalid optional parameter value', },
# 0x000000c5 - 0x000000fd reserved
    0x000000fe => { code => 'ESME_RDELIVERYFAILURE', msg => 'Delivery Failure (used for data_sm_resp)', },
    0x000000ff => { code => 'ESME_RUNKNOWNERR', msg => 'Unknown error', },
# 0x00000100 - 0x000003ff reserved for SMPP extension
# 0x00000400 - 0x000004ff reserved for SMSC vendor specific errors
# 0x00000500 - 0xffffffff reserved

### *** Dear reader: if you know more error codes, e.g. in the
###     vendor specific range, please let me know so we can teach
###     this module about them.

};


sub new {
	my ( $class, %params ) = @_;

	my $this = {}; 
	
	$this->{host} = $params{host};
  $this->{port} = $params{port}?$params{port}:2599;
  $this->{on_bound} = $params{on_bound}; 
  $this->{system_id} = $params{system_id}?$params{system_id}:'PearlSMPP'; 
  $this->{authentication} = $params{authentication}; 
  $this->{authorization} = $params{authorization};
  $this->{submit_sm} = $params{submit_sm}; 
  $this->{outbound_q} = $params{outbound_q}; 
  $this->{on_deliver_sm_resp} = $params{handle_deliver_sm_resp}; 
  $this->{disconnect} = $params{disconnect}; 
  $this->{debug} = $params{debug}?$params{debug}:undef; 
  $this->{reader} = undef; 
  $this->{connections} = {}; 

  $this->{tcp_server} = tcp_server ( 
    $this->{host}, 
    $this->{port}, 
    sub {
      my ( $socket, $fromhost, $fromport ) = @_; 
      # warn "Connect from $fromhost:$fromport\n" if $this->{debug}; 
      my $connection_id = $fromhost . ":" . $fromport; 
      $this->{connections}->{$connection_id}->{'state'} = 'OPEN'; 
      $this->{connections}->{$connection_id}->{'socket'} = $socket; 

      $this->{reader} = packet_reader ( $socket, 'N@!0', 1e6, sub {
          if (defined $_[0]) {
            $this->process_packet ( $socket, $fromhost, $fromport, $_[0]); 
          } elsif ($! == EPIPE) {
            $this->close_connection ( $fromhost, $fromport); 
          } else {
            # warn "Network error: $!"; 
            $this->close_connection ( $fromhost, $fromport); 
          }
      } );
      return;
    }, 
    sub {
          my ($fh, $thishost, $thisport) = @_;
          $this->{on_bound}($fh, $thishost, $thisport); 
    } 
  );

  $this->{timer} = AnyEvent->timer ( after => 5, cb => sub { $this->handle_outbound(); } , interval => 5); 

	return bless $this, 'Pearl::SMPP::Server';
}

sub close_connection {
  my ($this, $fromhost, $fromport) = @_; 
  #warn "Closing connection from $fromhost:$fromport\n" if $this->{debug}; 
  my $connection_id = $fromhost . ":" . $fromport; 
  delete $this->{connections}->{$connection_id}; 
  $this->{disconnect}($fromhost,$fromport); 

  return 1; 
}

sub process_packet {

	my ( $this, $socket, $fromhost, $fromport, $packet ) = @_;
  warn "PDU <- $fromhost:$fromport \n" if $this->{debug}; 
  _hexdump ($packet) if $this->{debug}; 

  my $pdu  = SMPP::Packet::unpack_pdu( $packet ); 
  warn "Unpacked PDU from $fromhost:$fromport\n" if $this->{debug}; 
  warn Dumper $pdu if $this->{debug}; 

  my $resp = $this->process_pdu ($socket, $fromhost, $fromport, $pdu); 
  if ($resp) { 
    syswrite $socket, $resp; 
    if ($this->{debug}) { 
      warn "PDU -> $fromhost:$fromport\n";
      _hexdump($resp);
      warn "Unpacked PDU to $fromhost:$fromport\n"; 
      warn Dumper SMPP::Packet::unpack_pdu( $resp );
    }
  } 

}

sub process_pdu { 
  my ( $this, $socket, $fromhost, $fromport, $pdu ) = @_; 

  my $pdu_cmd = "unknown";
  if ( cmd_tab->{ $pdu->{command_id} } ) {
      $pdu_cmd = cmd_tab->{ $pdu->{command_id} };
  }

  if ( $pdu_cmd eq 'enquire_link' ) {
      return $this->handle_enquire_link( $socket, $fromhost, $fromport, $pdu );
  } elsif ( $pdu_cmd eq 'bind_transmitter' ) { 
      return $this->handle_bind_transmitter ( $socket, $fromhost, $fromport, $pdu ); 
  } elsif ( $pdu_cmd eq 'bind_receiver') { 
      return $this->handle_bind_receiver ( $socket, $fromhost, $fromport, $pdu );
  } elsif ( $pdu_cmd eq 'bind_transceiver') { 
      return $this->handle_bind_transceiver ( $socket, $fromhost, $fromport, $pdu );
  } elsif ( $pdu_cmd eq 'unbind') { 
      return $this->handle_unbind ( $socket, $fromhost, $fromport, $pdu ); 
  } elsif ( $pdu_cmd eq 'submit_sm') { 
      return $this->handle_submit_sm ( $socket, $fromhost, $fromport, $pdu ); 
  } elsif ( $pdu_cmd eq 'submit_sm_multi') { 
      return $this->handle_submit_sm_sulti( $socket, $fromhost, $fromport, $pdu ); 
  } elsif ( $pdu_cmd eq 'generic_nack') { 
      return $this->handle_generic_nack( $socket, $fromhost, $fromport, $pdu ); 
  } elsif ( $pdu_cmd eq 'deliver_sm_resp') { 
      return $this->handle_deliver_sm_resp ( $socket, $fromhost, $fromport, $pdu ); 
  } else { 
      warn "Received unknown PDU from $fromhost:$fromport with command_id=".Dumper ($pdu->{command_id}) . "\n" if $this->{debug};
      return  $this->handle_generic_nack( $socket, $fromhost, $fromport, $pdu );    
  }

}

sub handle_deliver_sm_resp { 
  my ( $this, $socket, $fromhost, $fromport, $pdu ) = @_; 
  #warn 'Delete from MySQL something with message_id= or receipted_message_id='.$pdu->{'message_id'} if $this->{debug}; 

  return $this->{on_deliver_sm_resp}($fromhost,$fromport,$pdu); 
}

sub handle_generic_nack { 
  my ( $this, $socket, $fromhost, $fromport, $pdu ) = @_; 

  warn "Generic NACK for unknown PDU." if $this->{debug}; 

  return SMPP::Packet::pack_pdu ( { 
    version => 0x34, 
    seq => $pdu->{seq}, 
    command => 'generic_nack'
  } ); 
}

sub handle_submit_sm { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  my $connection_id = $fromhost . ":" . $fromport; 
  my $submit_sm_resp = undef; 

  # Check if client authenticated и в нужном состоянии
  if ( ( $this->{connections}->{$connection_id}->{'state'} ne 'BOUND_TX') 
    and ( $this->{connections}->{$connection_id}->{'state'} ne 'BOUND_TRX') ) { 
      $submit_sm_resp = SMPP::Packet::pack_pdu (
        { 
          version => 0x34, 
          status => ESME_RSUBMITFAIL, 
          seq => $pdu->{seq},
          command => 'submit_sm_resp',
          message_id => 0,
        }
      ); 
      return $submit_sm_resp; 
  }
  # Ему таки можно посылать сообщения 
  # Проверяем  А-имя 
  # my $system_id = $this->{connections}->{$connection_id}->{'system_id'}; 
  unless ( defined ( $this->{authorization}($fromhost,$fromport, $pdu->{'source_addr'}))) { 
      $submit_sm_resp = SMPP::Packet::pack_pdu (
        { 
          status => ESME_RINVSRCADR,  
          seq => $pdu->{seq},
          command => 'submit_sm_resp', 
          version => 0x34,
          message_id => 0,
        }
      ); 
      return $submit_sm_resp; 
  }

  my $message_id = $this->{submit_sm}($fromhost,$fromport, $pdu);
  unless ( defined ( $message_id ) ) { 
    $submit_sm_resp = SMPP::Packet::pack_pdu (
        { 
          status => ESME_RSUBMITFAIL, 
          seq => $pdu->{seq},
          command => 'submit_sm_resp', 
          version => 0x34,
          message_id => 0,
        }
      ); 
      return $submit_sm_resp; 
  }

  $submit_sm_resp = SMPP::Packet::pack_pdu (
    { 
        status => ESME_ROK, 
        seq => $pdu->{seq},
        command => 'submit_sm_resp', 
        version => 0x34,
        message_id => $message_id
      }
    ); 
  
  return $submit_sm_resp; 

}

sub handle_unbind { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  # warn Dumper $pdu if $this->{debug}; 

  my $unbind_resp = SMPP::Packet::pack_pdu ( 
    { 
      status => ESME_ROK, 
      seq => $pdu->{seq}, 
      command => 'unbind_resp', 
      version => 0x34
    }
  );

  return $unbind_resp; 
}

sub handle_bind { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  my $system_id = $pdu->{system_id}; 
  my $password = $pdu->{password};
  my $system_type = $pdu->{system_type}; 
  my $interface_version = $pdu->{interface_version}; 
  my $addr_ton = $pdu->{addr_ton}; 
  my $addr_npi = $pdu->{addr_npi}; 

  my $connection_id = $fromhost . ':' . $fromport; 

  # Проверяем на наличие этого пользователя в памяти и его состояние. 
  unless ( defined ( $this->{connections}->{$connection_id} ) )  { 
    return undef; 
  } # Непонятно как, но этот пользователь обошел состояние 'OPEN'

  # В самом простом случае никогда не проверяется TON, NPI. 
  # За последние 4 года ни разу не сталкивался. Поэтому пока просто игнорируем. 

  return $this->{authentication}($system_id, $password, $fromhost, $fromport); 

}

sub handle_bind_transmitter { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  my $connection_id = $fromhost . ":" . $fromport; 
  my $bind_transmitter_resp = undef; 

  unless ( defined ( $this->{connections}->{$connection_id} ) ) { return undef; }

  if ( $this->{connections}->{$connection_id}->{'state'} =~ 'BOUND') { 
      $bind_transmitter_resp = SMPP::Packet::pack_pdu ( { 
          status => ESME_RALYBND, 
          seq => $pdu->{seq}, 
          command_id => CMD_bind_transmitter_resp,
          command => 'bind_transmitter_resp', 
          system_id => $this->{'system_id'},
          version => 0x34
        }
      ); 
      return $bind_transmitter_resp; 
  }
  
  my $authentication = $this->handle_bind ( $socket, $fromhost, $fromport, $pdu );
  unless ( defined ( $authentication) ) { 
    $this->{connections}->{$connection_id}->{'state'} = 'OPEN'; 
    $bind_transmitter_resp = SMPP::Packet::pack_pdu ( 
      { 
        status => ESME_RINVPASWD,
        seq => $pdu->{seq}, 
        command_id => CMD_bind_transmitter_resp,
        command => 'bind_transmitter_resp', 
        system_id => $this->{'system_id'},
        version => 0x34
      }
    ); 
    
  } else { 
    $this->{connections}->{$connection_id}->{'state'} = 'BOUND_TX'; 
    $this->{connections}->{$connection_id}->{'system_id'} = $pdu->{'system_id'};
    $this->{connections}->{$connection_id}->{'authentication'} = $authentication;
    $bind_transmitter_resp = Pearl::SMPP::PDU->new ( 
      { 
        status => 0, 
        seq => $pdu->{seq}, 
        command_id => CMD_bind_transmitter_resp,
        command => 'bind_transmitter_resp', 
        system_id => $this->{'system_id'},
        version => 0x34
      }
    ); 

  }

  return $bind_transmitter_resp; 
 
}

sub handle_bind_receiver { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  my $connection_id = $fromhost . ":" . $fromport; 
  my $bind_receiver_resp = undef; 

  unless ( defined ( $this->{connections}->{$connection_id} ) ) { return undef; }

  if ( $this->{connections}->{$connection_id}->{'state'} =~ 'BOUND') { 
      $bind_receiver_resp = SMPP::Packet::pack_pdu ( { 
          status => ESME_RALYBND, 
          seq => $pdu->{seq}, 
          command_id => CMD_bind_receiver_resp,
          command => 'bind_receiver_resp', 
          system_id => $this->{'system_id'},
          version => 0x34
        }
      ); 
      return $bind_receiver_resp; 
  }

  my $authentication = $this->handle_bind ( $socket, $fromhost, $fromport, $pdu );
  unless ( defined ( $authentication ) ) { 
    $this->{connections}->{$connection_id}->{'state'} = 'OPEN'; 
    $bind_receiver_resp = SMPP::Packet::pack_pdu ( 
      { 
        status => ESME_RINVPASWD,
        seq => $pdu->{seq}, 
        command_id => CMD_bind_receiver_resp,
        command => 'bind_receiver_resp', 
        system_id => $this->{'system_id'},
        version => 0x34
      }
    ); 
    
  } else { 
    $this->{connections}->{$connection_id}->{'state'} = 'BOUND_RX'; 
    $this->{connections}->{$connection_id}->{'system_id'} = $pdu->{'system_id'};
    $this->{connections}->{$connection_id}->{'authentication'} = $authentication;

    $bind_receiver_resp = SMPP::Packet::pack_pdu ( 
      { 
        status => 0, 
        seq => $pdu->{seq}, 
        command_id => CMD_bind_receiver_resp,
        command => 'bind_receiver_resp', 
        system_id => $this->{'system_id'},
        version => 0x34
      }
    ); 

  }

  return $bind_receiver_resp; 
}

sub handle_bind_transceiver { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  my $connection_id = $fromhost . ":" . $fromport; 
  my $bind_transceiver_resp = undef; 

  unless ( defined ( $this->{connections}->{$connection_id} ) ) { return undef; }

  if ( $this->{connections}->{$connection_id}->{'state'} =~ 'BOUND') { 
      $bind_transceiver_resp = SMPP::Packet::pack_pdu ( { 
          status => ESME_RALYBND, 
          seq => $pdu->{seq}, 
          command_id => CMD_bind_transceiver_resp,
          command => 'bind_transceiver_resp', 
          system_id => $this->{system_id}
        }
      ); 
      return $bind_transceiver_resp;
  }

  my $authentication = $this->handle_bind ( $socket, $fromhost, $fromport, $pdu );
  unless ( defined ( $authentication ) ) { 
    $this->{connections}->{$connection_id}->{'state'} = 'OPEN'; 
    $bind_transceiver_resp = SMPP::Packet::pack_pdu ( 
      { 
        version => 0x34, 
        status => ESME_RINVPASWD,
        seq => $pdu->{seq}, 
        command_id => CMD_bind_transceiver_resp,
        command => 'bind_transceiver_resp', 
        system_id => $this->{system_id}
      }
    ); 
    
  } else { 
    $this->{connections}->{$connection_id}->{'state'} = 'BOUND_TRX'; 
    $this->{connections}->{$connection_id}->{'system_id'} = $pdu->{'system_id'};
    $this->{connections}->{$connection_id}->{'authentication'} = $authentication;

    $bind_transceiver_resp = SMPP::Packet::pack_pdu ( 
      { 
        version   => 0x34,
        status => 0, 
        seq => $pdu->{seq}, 
        command => 'bind_transceiver_resp', 
        system_id => $this->{system_id}
      }
    ); 

  }

  return $bind_transceiver_resp;

}

sub handle_enquire_link { 
  my ( $this, $socket, $fromhost, $fromport, $pdu) = @_; 

  my $enquire_link_resp = SMPP::Packet::pack_pdu ( 
    { 
      status => 0, 
      seq => $pdu->{seq}, 
      version => 0x34, 
      command => 'enquire_link_resp'
    }
  ); 

  return $enquire_link_resp; 

}

sub handle_outbound { 
  my ($this) = @_; 

  my $outbound = $this->{outbound_q}(); 
  unless ( defined ( keys %{ $outbound } )) { return undef; }

  #warn Dumper $outbound; 
  foreach my $system_id ( keys %{ $outbound }) { 
    my $messages = $outbound->{$system_id}; 
    #warn Dumper $messages; 
    next unless ( defined ( $messages ) ); 
    warn "Outbound ready to $system_id" if $this->{'debug'};  
    unless ( defined ( $this->_send_outbound($system_id, $messages) ) ) { 
      warn "Can't send outbound to $system_id"; 
    }
  }
}

sub _send_outbound { 
  my ($this, $system_id, $PDUs ) = @_; 

  my $socket = $this->_find_socket($system_id); 
  return undef unless defined $socket; 
  foreach my $id ( keys %{ $PDUs } ) { 
    warn "PDU -> $system_id:\n" . Dumper SMPP::Packet::unpack_pdu($PDUs->{$id}); 
    syswrite $socket, $PDUs->{$id};
  }
}

sub _find_socket { 
  my ($this, $system_id) = @_; 

  foreach my $connection_id ( %{ $this->{connections} } ) { 
    if ( defined ( $this->{connections}->{$connection_id}->{'system_id'} )) { 
      if ($this->{connections}->{$connection_id}->{'system_id'} eq $system_id) { 
        return $this->{connections}->{$connection_id}->{'socket'}; 
      }
    }
  } 
  return undef; 

}
sub _hexdump {
    local ($!, $@);
    no warnings qw(uninitialized);
    while ($_[0] =~ /(.{1,32})/smg) {
        my $line = $1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print STDERR "$_[1] ", join(" ", @c, '|', $line), "\n";
    }
    print STDERR "\n";
}


1;

__END__

=back

=head1 EXAMPLES

see examples/smppd_example.pl 

=head1 BUGS

Потенциальная бага. Потенциально можно уронить приложение послав на него много коннектов с разных портов, но обрывая их на стадии 
"до первого пакета". 

=head1 SEE ALSO

None

=head1 TODO


=head1 AUTHOR

Alex Radetsky <rad@rad.kiev.ua>

=cut


