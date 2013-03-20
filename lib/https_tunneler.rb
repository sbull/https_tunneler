require 'openssl'
require 'socket'

class HttpsTunneler
  class << self; attr_accessor :debug end
  @debug = nil

  attr_accessor :debug
  attr_accessor :server_port, :ssl_context, :client_port
  attr_accessor :thread, :tcp_server, :ssl_server
  attr_accessor :io_select_timeout, :io_start_timeout

  def self.generate_ssl_context(common_name=nil)
    # key = OpenSSL::PKey::RSA.new(File.read('cert.key'))
    # cert = OpenSSL::X509::Certificate.new(File.read('cert.pem'))
    common_name ||= 'localhost'
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = Time.now.to_i
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 3600
    cert.public_key = key.public_key
    cert.subject = OpenSSL::X509::Name.parse("CN=#{common_name}")
    context = OpenSSL::SSL::SSLContext.new
    context.verify_mode = OpenSSL::SSL::VERIFY_NONE
    context.cert = cert
    context.key = key
    context
  end

  def self.start_tunneler_thread(server_port, client_port=nil)
    tunnel = self.new(server_port, client_port)
    tunnel.run
    tunnel
  end

  def initialize(server_port, client_port=nil)
    self.server_port = server_port
    self.client_port = client_port
    self.io_select_timeout = 0.01
    self.io_start_timeout = 30
  end

  def run
    self.ssl_context ||= self.class.generate_ssl_context
    self.tcp_server ||= TCPServer.new(client_port||0)
    self.client_port = tcp_server.addr[1] # Refresh in case it wasn't set.
    self.thread = Thread.new do
      Thread.current.abort_on_exception = true # Don't hang with no connection.
      self.ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, ssl_context)
      run_server_loop
    end
  end

  def debug?
    debug || self.class.debug
  end


  private

  def run_server_loop
    loop do
      begin
        ssl_socket = ssl_server.accept
        request = nil
        stream_started = false
        # Tunnel the request to the listening HTTP server.
        TCPSocket.open('localhost', server_port) do |tcp_socket|
          read_socket(ssl_socket) do |chunk|
            if chunk
              request ||= ''
              request << chunk
            end
            # Stream the request body, only after the headers have been
            # modified and sent.
            if stream_started
              tcp_socket.write(chunk)
            else
              # See if the request header is ready to be updated.
              new_request = add_https_header_to_request(request)
              # If it was updated, send it.
              if new_request != request
                request = new_request
                tcp_socket.write(request)
                stream_started = true
              end
            end
          end
          if stream_started || request # Don't bother sending empty requests.
            # If the request was never sent, send it now.
            tcp_socket.write(request) unless stream_started
            # Close the socket for write and let the request be processed.
            tcp_socket.close_write
            log('REQUEST',request)
            Thread.pass
            # Retrieve the response and send it back.
            response = nil
            read_socket(tcp_socket, true) do |chunk|
              if chunk
                response ||= ''
                response << chunk
              end
              ssl_socket.write(chunk)
            end
            log('RESPONSE',response)
          end
        end
      rescue OpenSSL::SSL::SSLError => e
        log('ERROR', e.inspect)
      ensure
        ssl_socket.close if ssl_socket
      end
      Thread.pass # Let the response be processed.
    end
  end

  def read_socket(socket, block_for_start=nil, &block)
    io = socket.respond_to?(:io) ? socket.io : socket # SSLSocket#io
    data = nil
    should_retry = true
    read_maxlen = 100000
    begin
      loop do
        if block_for_start
          block_for_start = false
          chunk = Timeout::timeout(io_start_timeout) { socket.gets }
        else
          chunk = socket.read_nonblock(read_maxlen)
          should_retry = true
        end
        if block
          block.call(chunk)
        else
          data ||= ''
          data << chunk
        end
      end
    rescue => e
      log('ERROR', e.inspect)
      # Poltergeist/phantomjs on ubuntu blocks between header and body
      # of POST requests.
      if should_retry
        # Give the socket a chance to have more readable data.
        Thread.pass
        if IO.select([io], nil, nil, io_select_timeout)
          should_retry = false
          retry
        end
      end
    end
    data
  end

  def add_https_header_to_request(request)
    new_request = request
    if request
      # Check for the Host: header, and inject X-Forwarded-Proto: after it.
      pre, host, post = request.split(/(\r\nHost:[^\n]+\n)/, 2)
      if host
        new_request = pre+host+"X-Forwarded-Proto: https\r\n"+post
      end
    end
    new_request
  end

  def log(label, *msgs)
    if debug?
      lbl = "#{self.class}_#{label}_#{rand(1000000)}"
      # puts "ts=\"#{Time.now}\" msg=<<'#{lbl}'\n"+msgs.join("\n")+"\n#{lbl}"
      puts "ts=\"#{Time.now}\" msg=<<'#{lbl}'\n"+msgs.collect{|m| m.to_s.length > 10000 ? m.to_s[0,1000]+"\n\n...<SNIP #{m.to_s.length-2000}>...\n\n"+m.to_s[-1000,1000] : m.to_s }.join("\n")+"\n#{lbl}"
    end
  end

end
