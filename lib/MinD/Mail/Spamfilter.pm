use 5.014;
use warnings;

package MinD::Mail::Spamfilter;

use base 'Exporter';
our @EXPORT_OK = qw(
  QUARANTINE_PATH
  read_body
  read_header
  sanitized
  score
  spamdir
);

use File::Share qw(dist_dir);
use Mail::SpamAssassin;
use Path::Tiny qw(path);

use constant QUARANTINE_PATH => '/var/qmail/quarantine';

sub read_body {
    [<STDIN>];
}

sub read_header {
    my @header;
    while (<STDIN>) {
        last if $_ eq "\n";
        push @header, $_;
    }
    \@header;
}

sub sanitized {
    lc(shift) =~ y!+.0-9=@_a-z-!?!cr;
}

sub score {
    my ( $ar_header, $ar_body ) = @_;
    $ar_header //= read_header;
    $ar_body   //= read_body;

    state $rules_file = path( dist_dir('MinD-Mail-Spamfilter'), 'sa-rules' );
    my $spamtest =
      Mail::SpamAssassin->new( { site_rules_filename => $rules_file } )
      or die "Cannot create Mail::SpamAssassin object.\n";
    $spamtest->compile_now(0);    # keine user_prefs verwenden
    my $status = $spamtest->check_message_text( [ @$ar_header, @$ar_body ] );

    $ENV{MinD_Spam_Properties} = $status->get_names_of_tests_hit;
    $ENV{MinD_Spam_Score} = my $score = $status->get_score;
    if (wantarray) { $score, $status->get_names_of_tests_hit_with_scores_hash }
    else           { $score }
}

sub spamdir {
    path( QUARANTINE_PATH, spam => sanitized( shift // $ENV{SENDER} // '<>' ) );
}

1;
