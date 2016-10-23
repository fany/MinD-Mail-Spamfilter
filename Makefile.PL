use 5.014;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME      => 'MinD::Mail::Spamfilter',
    AUTHOR    => q{Martin H. Sluka <martin@sluka.de>},
    VERSION   => 1.3,
    EXE_FILES => [
        qw{
          bin/spam-quarantine
          bin/spam-quarantine2mbox
          bin/spam-score
          bin/spam-triage
          bin/strip_quarantined_mail
          }
    ],
    LICENSE            => 'Artistic_2_0',
    PL_FILES           => {},
    MIN_PERL_VERSION   => 5.014,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        'Digest::SHA1' => 0,
        'List::Util'   => 0,
        'Mail::Header' => 0,
        'Path::Tiny'   => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES    => 'MinD-Mail-Spamfilter-*' },
);
