use inc::Module::Install;

name            'REST-Client';
all_from        'lib/REST/Client.pm';

requires 'URI' => 0;
requires 'LWP::UserAgent' => 0;
requires 'Crypt::SSLeay' => 0;

WriteAll();
