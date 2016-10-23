use 5.02;
use warnings;

package MinD::Mail::Spamfilter::Plugin::SenderBlacklist;

use Mail::SpamAssassin::Plugin;

use base 'Mail::SpamAssassin::Plugin';

sub new {
    my $class        = shift;
    my $mailsaobject = shift;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless( $self, $class );

    $self->register_eval_rule('check_sender_blacklist');
    $self;
}

sub check_sender_blacklist {
    defined &MinD::Mail::Spamfilter::spamdir
      and defined( my $sender = $ENV{SENDER} )
      or return;
    MinD::Mail::Spamfilter::spamdir($sender)->exists;
}

1;
