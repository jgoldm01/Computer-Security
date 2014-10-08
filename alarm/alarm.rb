#!/usr/bin/ruby

require 'packetfu'
require 'base64'

$INCIDENTNUM = 0;

#-----------------------------------------------------------------------------#

def test_shellCode(line)
    line2 = line.clone
    #first check if there is an HTTP protocol attached, some legitimate sites
    #seem to involve the use of registers
    index = line2.index("HTTP")
    if index != nil
        return false
    end
    for i in 0..3
        index = line2.index("\\x")
        if index == nil
            return false
        else 
            line2.slice!(0..index)
        end
    end

    #printing the incident message, is different from the display_incident
    #because often there is no protocol
    $INCIDENTNUM += 1
    str = "#{$INCIDENTNUM}. ALERT: Shellcode is detected from #{get_ip(line)} "
    puts str

    return true
end

def test_nmap(line)
    index = line.index("N")
    if index != nil
        display_incident("NMAP scan", line)
        return true
    end
    return false
end

def test_http_err(line)
    index = line.index("\" 4")
    if index != nil
        display_incident("HTTP error", line)
        return true
    end
    return false
end

#returns the IP address of a line
def get_ip(line)
    str = ""
    line.each_char do |char|
        if char == " "
            return str
        else
            str += char
        end
    end
end

def get_protocol(line)
    str = ""
    quoteNum = 0;
    spaceNum = 0;
    line.each_char do |char|
        if char == "\""
            quoteNum += 1
        elsif quoteNum == 1
            if char == " "
                spaceNum += 1
            elsif spaceNum == 2
                if char == "/"
                    return str
                else
                    str += char
                end
            end
        end
    end
end

#returns a string of the protocol and payload, with quotes attached
def get_payload(line)
    str = ""
    quoteNum = 0;
    line.each_char do |char|
        if char == "\""
            quoteNum += 1
        end
        if quoteNum == 1
            str += char
        elsif quoteNum == 2
            str += char
            return str
        end
    end
end

def display_incident(type, line)
    $INCIDENTNUM += 1
    str = "#{$INCIDENTNUM}. ALERT: #{type} is detected from #{get_ip(line)} "\
          "(#{get_protocol(line)}) (#{get_payload(line)})!"
    puts str
end

#-----------------------------------------------------------------------------#

#is potentially a NULL scan if none of the flags are on
def is_NULL?(pck)
    if pck.tcp_flags.urg || pck.tcp_flags.ack || pck.tcp_flags.psh \
    || pck.tcp_flags.rst || pck.tcp_flags.syn || pck.tcp_flags.fin
        return false
    else
        return true
    end    
end

#is an XMAS flag collection if urg, psh, and fin flags are on but no others
def is_XMAS?(pck)
    if (pck.tcp_flags.urg && pck.tcp_flags.psh && pck.tcp_flags.fin) &&
    !(pck.tcp_flags.ack || pck.tcp_flags.rst || pck.tcp_flags.syn)
        return true
    else
        return false
    end
end

#prints the error message if it recieves 10 of the same type of suspicious 
#packet in a row from the same ip address
def susp_ip(pck, ipSource, sameSourceCount, type, newType)
    if (pck.ip_saddr == ipSource) && (type == newType)
        sameSourceCount += 1
        if sameSourceCount == 10
            display_live_incident(newType, pck)
        end
    else
        ipSource = pck.ip_saddr
        sameSourceCount = 0;
    end
    return ipSource, sameSourceCount, newType
end

def display_live_incident(type, pck)
    $INCIDENTNUM += 1
    
    if pck.is_udp?
        protocol = "UDP"
    elsif pck.is_tcp?
        protocol "HTTP"
    end
    
    payload = Base64.encode64(pck.payload)
    
    str = "#{$INCIDENTNUM}. ALERT: #{type} is detected from #{pck.ip_saddr} "\
          "(#{protocol}) (#{payload})!"
    puts str
end

#-----------------------------------------------------------------------------#

#main
if __FILE__ == $0
#if there are command line arguments for reading in a server log
if ARGV.length > 1
    log = File.open(ARGV[1], "r")
    #p [*log][1]
    log.each_line do |line|
        test_shellCode(line)
        test_nmap(line)
        test_http_err(line)
    end        
else
    ipSource = 0
    sameSourceCount = 0
    type = ""
    cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    cap.stream.each do |p|
        pck = PacketFu::Packet.parse p
        if pck.is_ip?
            if defined? pck.tcp_flags
                if is_NULL?(pck)
                    ipSource, sameSourceCount, type \
                    = susp_ip(pck, ipSource, sameSourceCount, type, "Null scan")
                elsif is_XMAS?(pck)
                    ipSource, sameSourceCount, type \
                    = susp_ip(pck, ipSource, sameSourceCount, type, "XMAS scan")
                end
            end
        end 
    end
end
end


#stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
#stream.show_live()
