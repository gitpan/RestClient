package REST::Client;

=head1 NAME

REST::Client - A simple client for interacting with RESTful http/https resources

=head1 SYNOPSIS

 use REST::Client;
 
 #The basic use case
 my $client = REST::Client->new();
 $client->GET('http://example.com/dir/file.xml');
 print $client->responseContent();
  
 #A host can be set for convienience
 $client->setHost('http://example.com');
 $client->PUT('/dir/file.xml', '<example>new content</example>');
 if( $client->responseCode() eq '200' ){
     print "Deleted\n";
 }
  
 #custom request headers may be added
 $client->addHeader('CustomHeader', 'Value');
  
 #response headers may be gathered
 print $client->responseHeader('ResponseHeader');
  
 #X509 client authentication
 $client->setCert('/path/to/ssl.crt');
 $client->setKey('/path/to/ssl.key');
  
 #add a CA to verify server certificates
 $client->setCa('/path/to/ca.file');
  
 #you may set a timeout on requests, in seconds
 $client->setTimeout(10);
  
 #options may be passed as well as set
 $client = REST::Client->new({
         host    => 'https://example.com',
         cert    => '/path/to/ssl.crt',
         key     => '/path/to/ssl.key',
         ca      => '/path/to/ca.file',
         timeout => 10,
     });
 $client->GET('/dir/file', {CustomHeader => 'Value'});
  
 #Requests can be specificed directly as well
 $client->request('GET', '/dir/file', 'request body content', {CustomHeader => 'Value'});

=head1 DESCRIPTION

REST::Client provides a simple way to interact with HTTP RESTful resources.

=cut

=head1 METHODS

=over 4

=cut

use strict;
use warnings;
use 5.008_000;

use constant TRUE => 1;
use constant FALSE => 0;

our ($VERSION) = ('$Rev: 60 $' =~ /(\d+)/);

use URI;
use LWP::UserAgent;
use Carp qw(croak carp);
use Crypt::SSLeay;


=item new ( [%$config] )

Construct a new REST::Client. Takes an optional hash or hash reference or config flags:

=over 4

=item host

A default host that will be prepended to all requests.  Allows you to just specify the path when making requests.

=item timeout

A timeout in seconds for requests made with the client.  After the timeout the client will return a 500.

=item cert

The path to a X509 certificate file to be used for client authentication.

=item key

The path to a X509 key file to be used for client authentication.

=item ca

The path to a certificate authority file to be used to verify host certificates.

=back

=cut

sub new {
    my $class = shift;
    my $config;

    $class->_buildAccessors();

    if(ref $_[0] eq 'HASH'){
        $config = shift;
    }elsif(scalar @_ && scalar @_ % 2 == 0){
        $config = {@_};
    }else{
        $config = {};
    }

    my $self = bless({}, $class);
    $self->{'_config'} = $config;

    return $self;
}

=item GET ( $url, [%$headers] )

Preform an HTTP GET to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub GET {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('GET', $url, undef, $headers);
}

=item PUT ($url, [$body_content, %$headers] )

Preform an HTTP PUT to the resource specified. Takes an optional body content and hashref of custom request headers.

=cut

sub PUT {
    my $self = shift;
    return $self->request('PUT', @_);
}

=item POST ( $url, [$body_content, %$headers] )

Preform an HTTP POST to the resource specified. Takes an optional body content and hashref of custom request headers.

=cut

sub POST {
    my $self = shift;
    return $self->request('PUT', @_);
}

=item DELETE ( $url, [%$headers] )

Preform an HTTP DELETE to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub DELETE {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('DELETE', $url, undef, $headers);
}

=item OPTIONS ( $url, [%$headers] )

Preform an HTTP OPTIONS to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub OPTIONS {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('OPTIONS', $url, undef, $headers);
}

=item HEAD ( $url, [%$headers] )

Preform an HTTP HEAD to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub HEAD {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('HEAD', $url, undef, $headers);
}

=item addHeader ( $header_name, $value )

Add a custom header to the next request.

=cut

sub addHeader {
    my $self = shift;
    my $header = shift;
    my $value = shift;
    
    my $headers = $self->{'_headers'} || {};
    $headers->{$header} = $value;
    $self->{'_headers'} = $headers;
    return;
}

=item request ( $method, $url, [$body_content, %$headers] )

Issue a custom request, providing all possible values.

=cut


sub request {
    my $self = shift;
    my $method  = shift;
    my $url     = shift;
    my $content = shift;
    my $headers = shift;

    $self->{'_res'} = undef;


    #error check
    croak "REST::Client exception: First argument to request must be one of GET, PUT, POST, DELETE, OPTIONS, HEAD" unless $method =~ /^(get|put|post|delete|options|head)$/i;
    croak "REST::Client exception: Must provide a url to $method" unless $url;
    croak "REST::Client exception: headers must be presented as a hashref" if $headers && ref $headers ne 'HASH';


    #build UA
    $url = $self->_prepareURL($url);

    #to ensure we use our desired SSL lib
    my $tmp_socket_ssl_version = $IO::Socket::SSL::VERSION;
    $IO::Socket::SSL::VERSION = undef;

    my $ua = LWP::UserAgent->new;
    $ua->agent("REST::Client/$VERSION");
    $ua->timeout($self->getTimeout) if $self->getTimeout;
    my $req = HTTP::Request->new( $method => $url );

    #build headers
    if($content){
        $req->content($content);
        $req->header('Content-Length', length($content));
    }else{
        $req->header('Content-Length', 0);
    }

    my $custom_headers = $self->{'_headers'} || {};
    for my $header (keys %$custom_headers){
        $req->header($header, $custom_headers->{$header});
    }

    for my $header (keys %$headers){
        $req->header($header, $headers->{$header});
    }


    #prime LWP with ssl certfile if we have values
    if($self->getCert){
        carp "REST::Client exception: Certs defined but not using https" unless $url =~ /^https/;

        croak "REST::Client exception: Cannot read cert and key file" unless -f $self->getCert && -f $self->getKey;
        $ENV{'HTTPS_CERT_FILE'} = $self->getCert;
        $ENV{'HTTPS_KEY_FILE'}  = $self->getKey; 
        if(my $ca = $self->getCa){
            croak "REST::Client exception: Cannot read CA file" unless -f $ca;
            $ENV{'HTTPS_CA_FILE'}  = $ca
        }
    }

    my $res = $ua->request($req);
    $IO::Socket::SSL::VERSION = $tmp_socket_ssl_version;

    $self->{_res} = $res;

    return $self;
}

=item responseCode ()

Return the HTTP response code of the last request

=cut

sub responseCode {
    my $self = shift;
    return $self->{_res}->code;
}

=item responseContent ()

Return the response body content of the last request

=cut

sub responseContent {
    my $self = shift;
    return $self->{_res}->content;
}

=item responseHeader ()

Return the HTTP headers from the last response

=cut

sub responseHeader {
    my $self = shift;
    my $header = shift;
    croak "REST::Client exception: no header provided to responseHeader" unless $header;
    return $self->{_res}->header($header);
}

=item buildQuery ( [...] )

A convienience wrapper around URI::query_form for building query strings. See L<URI>

=cut

sub buildQuery {
    my $self = shift;

    my $uri = URI->new();
    $uri->query_form(@_);
    return $uri->as_string();
}

=item responseXpath ()

A convienience wrapper that returns a L<XML::LibXML> xpath context for the body content.  Assumes the content is XML.

=cut

sub responseXpath {
    my $self = shift;

    require XML::LibXML;

    my $xml= XML::LibXML->new();
    $xml->load_ext_dtd(0);
    return $xml->parse_html_string( $self->responseContent() );
}


sub _prepareURL {
    my $self = shift;
    my $url = shift;

    my $host = $self->getHost;
    if($host){
        $url = '/'.$url unless $url =~ /^\//;
        $url = $host . $url;
    }
    unless($url =~ /^\w+:\/\//){
        $url = ($self->getCert ? 'https://' : 'http://') . $url;
    }

    return $url;
}

sub _buildAccessors {
    my $self = shift;

    return if $self->can('setHost');

    my @attributes = qw(Host Key Cert Ca Timeout);

    for my $attribute (@attributes){
        my $set_method = "
        sub {
        my \$self = shift;
        \$self->{'_config'}{lc('$attribute')} = shift;
        return \$self->{'_config'}{lc('$attribute')};
        }";

        my $get_method = "
        sub {
        my \$self = shift;
        return \$self->{'_config'}{lc('$attribute')};
        }";


        {
            no strict 'refs';
            *{'REST::Client::set'.$attribute} = eval $set_method ;
            *{'REST::Client::get'.$attribute} = eval $get_method ;
        }

    }

    return;
}

1;

=back

=head1 TODO

Caching, content-type negotiation, readable handles for body content.

=head1 AUTHOR

Miles Crawford, E<lt>mcrawfor@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2008 - 2009 by Miles Crawford.

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

