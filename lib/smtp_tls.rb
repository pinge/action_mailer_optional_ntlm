require "openssl"
require "net/smtp"
require "net/ntlm"

Net::SMTP.class_eval do
  
  def self.start( address, port = nil,
                  helo = 'localhost.localdomain',
                  user = nil, secret = nil, authtype = nil, use_tls = false,
                  &block) # :yield: smtp
    new(address, port).start(helo, user, secret, authtype, use_tls, &block)
  end

  def start( helo = 'localhost.localdomain',
             user = nil, secret = nil, authtype = nil, use_tls = false ) # :yield: smtp
    start_method = use_tls ? :do_tls_start : :do_start
    if block_given?
      begin
        send start_method, helo, user, secret, authtype
        return yield(self)
      ensure
        do_finish
      end
    else
      send start_method helo, user, secret, authtype
      return self
    end
  end

  private
  
  def do_tls_start(helodomain, user, secret, authtype)
    raise IOError, 'SMTP session already started' if @started
    
    ## This won't work outside of Rails.
    if Kernel::VERSION == '1.8.6'
      check_auth_args user, secret, authtype if user or secret
    elsif Kernel::VERSION == '1.8.7'
      check_auth_args user, secret
    end

    sock = timeout(@open_timeout) { TCPSocket.open(@address, @port) }
    @socket = Net::InternetMessageIO.new(sock)
    @socket.read_timeout = 60 #@read_timeout
    @socket.debug_output = STDERR #@debug_output

    check_response(critical { recv_response() })
    do_helo(helodomain)

    raise 'openssl library not installed' unless defined?(OpenSSL)
    starttls
    ssl = OpenSSL::SSL::SSLSocket.new(sock)
    ssl.sync_close = true
    ssl.connect
    @socket = Net::InternetMessageIO.new(ssl)
    @socket.read_timeout = 60 #@read_timeout
    @socket.debug_output = STDERR #@debug_output
    do_helo(helodomain)

    authenticate user, secret, authtype if user
    @started = true
  ensure
    unless @started
      # authentication failed, cancel connection.
        @socket.close if not @started and @socket and not @socket.closed?
      @socket = nil
    end
  end

  def do_helo(helodomain)
     begin
      if @esmtp
        ehlo helodomain
      else
        helo helodomain
      end
    rescue Net::ProtocolError
      if @esmtp
        @esmtp = false
        @error_occured = false
        retry
      end
      raise
    end
  end

  def starttls
    getok('STARTTLS')
  end

  def quit
    begin
      getok('QUIT')
    rescue EOFError, OpenSSL::SSL::SSLError
    end
  end

  def auth_ntlm(user, secret)
    res = critical {
      line = check_response(get_response('AUTH NTLM %s', Net::NTLM::Message::Type1.new().encode64), true) # send NTLM Type1 Message and receive NTLM Type2 Message
      get_response(Net::NTLM::Message.decode64(line.split(/ /)[1]).response({:user => user, :password => secret}, {:ntlmv2 => true}).encode64) # send NTLM Type3 Message
    }
    raise SMTPAuthenticationError, res unless /\A2../ === res
  end

end
