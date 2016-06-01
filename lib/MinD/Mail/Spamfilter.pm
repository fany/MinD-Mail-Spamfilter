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

use List::Util qw(sum);
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
    my $mh = my::Mail::Header->new($ar_header)
      or die "Cannot create my::Mail::Header object.\n";

    my %score4;

    # Die Subject-Regeln sind eher historisch, da diese Art Spam-Mails zu
    # Beginn (August 2015) tatsächlich recht eindeutig einfach am Subject
    # erkennbar waren. Mittlerweile könnte man darauf wohl verzichten:
    ++$score4{'subject prefix'} if $mh->normalized('Subject') =~ /\bFw:\s+/;
    $score4{subject} += 2
      if $mh->normalized('Subject') =~
/\bFw:\s+(?:try\s+it\s+out|important|news|read\s+this|new\s+(?:important\s+)?message)\b|^something new, don't miss up$/;
    ++$score4{'many recipients'} if $mh->normalized('To') =~ y/,// > 3;
    ++$score4{'many recipients'} if $mh->normalized('To') =~ y/,// > 6;
    ++$score4{'content language'}
      if $mh->normalized('Content-Language') eq 'en-us';
    ++$score4{charset} if 1 < grep /\bcharset="us-ascii"/, @$ar_body;

    # Das funktioniert so natürlich nur, wenn die Mail nicht unterwegs
    # umkodiert wurde, was aber in der mensa.de-Praxis eher selten passiert:
    ++$score4{msword}
      if grep $_ eq
qq(<html xmlns:v=3D"urn:schemas-microsoft-com:vml" xmlns:o=3D"urn:schemas=\n),
      @$ar_body;

    if ( defined( my $sender = $ENV{SENDER} ) ) {
        $score4{'known spam sender'} += 2 if spamdir($sender)->exists;
    }

    $ENV{MinD_Spam_Properties} = join ', ',
      map $_ . ( $score4{$_} != 1 && " ($score4{$_})" ), sort keys %score4;
    $ENV{MinD_Spam_Score} = my $score = sum( values %score4 ) // 0;
    if (wantarray) { $score, \%score4 }
    else           { $score }
}

sub spamdir {
    path( QUARANTINE_PATH, spam => sanitized( shift // $ENV{SENDER} // '<>' ) );
}

{

    package my::Mail::Header;
    use base 'Mail::Header';

    use Encode qw(decode);

    sub normalized {
        my $self = shift;
        defined( my $header = $self->get(@_) ) or return '';
        chomp( $header = decode( 'MIME-Header', $header ) );
        $header;
    }
}

1;
