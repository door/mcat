#!/usr/bin/env ruby
# coding: utf-8

require 'optparse'
require 'socket'
require 'uri'
require 'digest'
require 'tempfile'
require 'net/http'
require 'ipaddr'


$VERBOSE = false


def main
  options = {}

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} -a ADDRESS -c URL -v"

    opts.on("-a", "--address UDP_GROUP_ADDRESS", "Multicast group IP:PORT") do |address|
      unless address =~ /^udp:\/\//
        address = "udp://#{address}"
      end
      options[:udp_uri] = URI.parse(address)
    end

    opts.on("-c", "--control-url URL", "Control URL") do |url|
      options[:control_url] = url
    end

    opts.on("-v", "--verbose", "Verbose") do |v|
      $VERBOSE = true
    end
  end

  parser.parse!

  unless [:control_url, :udp_uri].all? {|k| options[k]}
    puts parser
    exit 1
  end

  socket = UDPSocket.new
  socket.bind(options[:udp_uri].host, options[:udp_uri].port)

  if IPAddr.new("224.0.0.0/4").include?(IPAddr.new(options[:udp_uri].host))
    membership = IPAddr.new(options[:udp_uri].host).hton + IPAddr.new("0.0.0.0").hton
    socket.setsockopt(:IPPROTO_IP, :IP_ADD_MEMBERSHIP, membership)
  end

  http_req = HttpReq.new(options[:control_url])

  info = http_req.get "/info"

  # blocksize filesize filename
  m = info.match(/^(\d+)\s+(\d+)\s+(\S.*)$/) or
    raise "Invalid info srting: #{info}"

  blocksize = m[1].to_i
  filesize  = m[2].to_i
  filename  = m[3]

  raise "Invalid blocksize #{m[1].inspect}" if blocksize == 0
  raise "Invalid filesize #{m[2].inspect}" if filesize == 0
  raise "File #{filename.inspect} exists" if File.exist?(filename)

  puts "File: #{filename}"
  puts "Size: #{filesize}"
  puts "Block size: #{blocksize}"
  puts

  saver = Saver.new blocksize, filesize, filename

  loop do
    pkt = socket.recv 100000
    break unless saver . add_pkt pkt
  end

  saver . missed_blocks . each do |blockno|
    s = http_req.get("/block/#{blockno}")
    saver . add_block blockno, s
    saver . flush
  end

  server_hash = http_req.get "/hash"
  local_hash = saver . hash . to_s

  if server_hash == local_hash
    saver . rename
    puts "File #{filename} received successfully"
  else
    puts "File received with errors"
  end
end


class HttpReq
  def initialize control_url
    @control_url = control_url
  end
  #
  #
  def get path
    notified = false
    loop do
      uri = URI.parse(@control_url + path)
      resp = Net::HTTP.get_response(uri)
      case resp.code.to_i
      when 200
        break resp.body
      when 424
        if not notified
          puts "Setver response not ready, waiting"
          notified = true
        end
        sleep 5
        next
      else
        raise "Unexpected http response #{resp.inspect} from #{uri}"
      end
    end
  end
end


class Saver
  def initialize blocksize, filesize, filename
    @blocksize = blocksize
    @filesize  = filesize
    @filename  = filename
    @buf = ""
    @b0 = nil # номер первого пакета в буфере
    @b1 = nil # номер предыдущего пакета в буфере

    # количество полных блоков в файле
    @full_blocks = @filesize / @blocksize
    # размер последнего пакета
    @last_block_size = @filesize % @blocksize
    # общее количество блоков
    @total_blocks = @full_blocks + (@last_block_size > 0 ? 1 : 0)

    @received = {}
  end
  #
  #
  def add_pkt pkt
    raise "too small" unless pkt.size > 4
    blockno, s = pkt.unpack("Na*")
    if @received[blockno]
      puts "DEBUG block #{blockno} already received" if $VERBOSE
      flush
      return
    end
    add_block blockno, s
    puts "DEBUG block #{blockno} added from UDP" if $VERBOSE
    true
  end
  #
  #
  def add_block blockno, s
    # check block size
    if blockno < @full_blocks
      expect = @blocksize
    elsif blockno == @full_blocks
      expect = @last_block_size
    else
      raise "Invalid block number #{blockno}"
    end
    raise "Invalid payload size #{s.size}. Expected: #{expect}" unless s.size == expect

    @b0 ||= blockno

    # flush if out-of-order pkt
    if @b1 && blockno != @b1+1
      flush
      @b0 = blockno
    end

    @buf << s

    # flush if fill the buffer
    if @buf.size >= 5000000
      flush
    else
      @b1 = blockno
    end

    # mark the block as received
    @received[blockno] = true

  end
  #
  #
  def flush
    @file ||= Tempfile.create("tempfile.#{@filename}", ".")
    @filepos ||= 0
    pos = @blocksize * @b0
    if @filepos != pos
      @file . sysseek(pos)
      @filepos = pos
      puts "b0: #{@b0}/#{@total_blocks} pos: #{@filepos}"
    end
    w = @file . syswrite(@buf)
    @filepos += w

    @b0 = nil
    @buf = ""
  end
  #
  #
  def missed_blocks
    (0 .. @total_blocks-1) . select {|i| not @received[i]}
  end
  #
  #
  def hash
    Digest::SHA1.file @file
  end
  #
  #
  def rename
    @file.close()
    File.rename(@file.path, @filename)
  end
end



main
