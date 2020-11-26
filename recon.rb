#!/usr/bin/env ruby
require 'erb'
require 'nmap/program'
require 'colorize'
require 'artii'
require 'sculpt'

puts "\n\n"
puts ' _______                                          '.colorize(:light_blue)
puts '/       \                                         '.colorize(:light_blue)
puts '$$$$$$$  |  ______    _______   ______   _______  '.colorize(:light_blue)
puts '$$ |__$$ | /      \  /       | /      \ /       \ '.colorize(:light_blue)
puts '$$    $$< /$$$$$$  |/$$$$$$$/ /$$$$$$  |$$$$$$$  |'.colorize(:light_blue)
puts '$$$$$$$  |$$    $$ |$$ |      $$ |  $$ |$$ |  $$ |'.colorize(:light_blue)
puts '$$ |  $$ |$$$$$$$$/ $$ \_____ $$ \__$$ |$$ |  $$ |'.colorize(:light_blue)
puts '$$ |  $$ |$$       |$$       |$$    $$/ $$ |  $$ |'.colorize(:light_blue)
puts '$$/   $$/  $$$$$$$/  $$$$$$$/  $$$$$$/  $$/   $$/ '.colorize(:light_blue)
puts '--------------------- @bagels --------------------'.colorize(:white)

subnet  = ARGV[0]
zone_transfer_domain = ARGV[1]
dirs = ["output",
	"./output/DNS",
        "./output/ALIVE",
        "./output/SMTP",
        "./output/SMB",
        "./output/SERVICE_SCANS",
        "./output/NFS",
        "./output/HTTP",
        "./output/FTP"]

dirs.each do |dir|
        Dir.mkdir(dir) unless File.exists?(dir)
end

def unique_file(path,port)
	system(`cat #{path} | grep "^Host:" | grep "#{port}/open" | awk '{print $2}' >> #{path} | sort -u #{path} > #{path}`)
end

def initial_recon(subnet)
	puts "\n ____ Initial Recon ____".white
	puts "\n  [+] Running Ping Sweep".green
	system(`nmap -PE -sn -n #{subnet} -oG - | awk '/Up$/{print $2}' >> ./output/ALIVE/alive_hosts.txt | sort -u ./output/ALIVE/alive_hosts.txt > ./output/ALIVE/alive_hosts.txt`)
	ping_sweep = Nmap::Program.scan do |nmap_ping_sweep|
			nmap_ping_sweep.ping 	= true
			nmap_ping_sweep.disable_dns = true
			nmap_ping_sweep.icmp_echo_discovery = true
			nmap_ping_sweep.quiet 	= true
			nmap_ping_sweep.xml 	= './output/ALIVE/alive_hosts.xml'
			nmap_ping_sweep.targets = subnet	
		     end
	system('xsltproc ./output/ALIVE/alive_hosts.xml -o ./reports/alive_hosts.html')

	puts "  [+] Running Quick TCP Scan".green	
	quick_tcp = Nmap::Program.scan do |nmap_quick_tcp|
			nmap_quick_tcp.disable_dns = true
			nmap_quick_tcp.quiet	= true
			nmap_quick_tcp.xml     	= './output/SERVICE_SCANS/quick_tcp.xml'
			nmap_quick_tcp.syn_scan = true
			nmap_quick_tcp.show_open_ports = true
			nmap_quick_tcp.os_fingerprint = true
			nmap_quick_tcp.default_script = true
			nmap_quick_tcp.target_file = './output/ALIVE/alive_hosts.txt'
			nmap_quick_tcp.fast 	 = true
			nmap_quick_tcp.top_ports = 2000
	end
	system('xsltproc ./output/SERVICE_SCANS/quick_tcp.xml -o ./reports/quick_tcp.html')

	puts "  [+] Scanning For DNS Servers".green	
	dns_sweep = Nmap::Program.scan do |nmap_dns_sweep|
			nmap_dns_sweep.disable_dns = true
                        nmap_dns_sweep.quiet       = true
			nmap_dns_sweep.syn_scan    = true
			nmap_dns_sweep.udp_scan    = true
                        nmap_dns_sweep.show_open_ports = true
			nmap_dns_sweep.target_file = './output/ALIVE/alive_hosts.txt'
			nmap_dns_sweep.ports = 53
			nmap_dns_sweep.grepable = './output/DNS/dns_servers.txt'
	end
	unique_file('./output/DNS/dns_servers.txt', '53')

	puts "  [+] Scanning For SMB/Samba Services".green
	smb_sweep = Nmap::Program.scan do |nmap_smb_sweep|
                        nmap_smb_sweep.disable_dns = true
                        nmap_smb_sweep.quiet       = true
                        nmap_smb_sweep.syn_scan    = true
			nmap_smb_sweep.show_open_ports = true
                        nmap_smb_sweep.target_file = './output/ALIVE/alive_hosts.txt'
                        nmap_smb_sweep.ports = [445, 139]
			nmap_smb_sweep.grepable = './output/SMB/smb_servers.txt'
	end
	unique_file('./output/SMB/smb_servers.txt','445')

	puts "  [+] Scanning For SMTP Services".green
	smtp_sweep = Nmap::Program.scan do |nmap_smtp_sweep|
			nmap_smtp_sweep.disable_dns = true
			nmap_smtp_sweep.quiet       = true
			nmap_smtp_sweep.syn_scan    = true
			nmap_smtp_sweep.show_open_ports = true
			nmap_smtp_sweep.target_file = './output/ALIVE/alive_hosts.txt'
			nmap_smtp_sweep.ports = 25
			nmap_smtp_sweep.grepable = './output/SMTP/smtp_servers.txt'
	end
	system(`cat ./output/SMTP/smtp_servers.txt | grep "^Host:" | grep "25/open" | awk '{print $2}' >> ./output/SMTP/smtp_servers.txt | sort -u ./output/SMTP/smtp_servers.txt > ./output/SMTP/smtp_servers.txt`)
	
	puts "  [+] Scanning For NFS Services".green
	nfs_sweep = Nmap::Program.scan do |nmap_nfs_sweep|
			nmap_nfs_sweep.disable_dns = true
			nmap_nfs_sweep.quiet       = true
			nmap_nfs_sweep.syn_scan    = true
			nmap_nfs_sweep.show_open_ports = true
			nmap_nfs_sweep.target_file = './output/ALIVE/alive_hosts.txt'
			nmap_nfs_sweep.ports = 111
			nmap_nfs_sweep.grepable = './output/NFS/nfs_servers.txt'
	end
	unique_file('./output/NFS/nfs_servers.txt','111')
	
	puts "  [+] Scanning For FTP Services".green
	ftp_sweep = Nmap::Program.scan do |nmap_ftp_sweep|
			nmap_ftp_sweep.disable_dns = true
			nmap_ftp_sweep.quiet       = true
			nmap_ftp_sweep.syn_scan    = true
			nmap_ftp_sweep.show_open_ports = true
			nmap_ftp_sweep.target_file = './output/ALIVE/alive_hosts.txt'
			nmap_ftp_sweep.ports = 21
			nmap_ftp_sweep.grepable = './output/FTP/ftp_servers.txt'
	end
	unique_file('./output/FTP/ftp_servers.txt','21')

	puts "  [+] Scanning For HTTP Services".green
	http_sweep = Nmap::Program.scan do |nmap_http_sweep|
			nmap_http_sweep.disable_dns = true
			nmap_http_sweep.quiet       = true
			nmap_http_sweep.syn_scan    = true
			nmap_http_sweep.show_open_ports = true
			nmap_http_sweep.target_file = './output/ALIVE/alive_hosts.txt'
			nmap_http_sweep.ports = [80,443]
			nmap_http_sweep.grepable = './output/HTTP/http_servers.txt'
	end
	unique_file('./output/HTTP/http_servers.txt','80')
end

def smb_enum()
	puts "\n ____ Service Enum ____".white
	puts "\n  [+] Enumerating SMB Shares".blue
	smb_share_enum = Nmap::Program.scan do |nmap_share_enum|
			nmap_share_enum.disable_dns = true
			nmap_share_enum.quiet       = true
			nmap_share_enum.syn_scan    = true
			nmap_share_enum.show_open_ports = true
			nmap_share_enum.target_file = './output/SMB/smb_servers.txt'
			nmap_share_enum.ports = [139,445]
			nmap_share_enum.script = 'smb-enum-shares'
			nmap_share_enum.xml = "./output/SERVICE_SCANS/smb_share_enum.xml"	
	end
	system("xsltproc ./output/SERVICE_SCANS/smb_share_enum.xml -o ./reports/smb_share_enum.html")
	
	puts "\n  [+] Enumerating SMB Users".blue
	smb_user_enum = Nmap::Program.scan do |nmap_user_enum|
			nmap_user_enum.disable_dns = true
			nmap_user_enum.quiet       = true
			nmap_user_enum.syn_scan    = true
			nmap_user_enum.show_open_ports = true
			nmap_user_enum.target_file = './output/SMB/smb_servers.txt'
			nmap_user_enum.ports = [139,445]
			nmap_user_enum.script = 'smb-enum-users.nse'
			nmap_user_enum.xml = "./output/SERVICE_SCANS/smb_user_enum.xml"
	end
	system("xsltproc ./output/SERVICE_SCANS/smb_user_enum.xml -o ./reports/smb_user_enum.html")

	puts "\n  [+] Running SMBClient".blue

end

def smtp_enum()
	puts "\n  [+] Enumerating SMTP Commands".blue
	smtp_command_enum = Nmap::Program.scan do |nmap_smtp_enum|
			nmap_smtp_enum.disable_dns = true
			nmap_smtp_enum.quiet       = true
			nmap_smtp_enum.syn_scan    = true
			nmap_smtp_enum.show_open_ports = true
			nmap_smtp_enum.target_file = './output/SMTP/smtp_servers.txt'
			nmap_smtp_enum.ports = 25
			nmap_smtp_enum.script = 'smtp-commands.nse'
			nmap_smtp_enum.xml = "./output/SERVICE_SCANS/smtp_command_enum.xml"
	end
	system("xsltproc ./output/SERVICE_SCANS/smtp_command_enum.xml -o ./reports/smtp_command_enum.html")
end

def zone_xfer(domain)
	puts "\n  [+] Testing DNS Zone Transfer".yellow
	dns_servers=File.open('./output/DNS/dns_servers.txt').read
        dns_servers.gsub!(/\r\n?/, "\n")
        dns_servers.each_line do |dns_server|
                puts `dig @#{dns_server} #{domain} AXFR > ./output/DNS/zone_transfers.txt 2>&1`
        end
end

begin
	initial_recon(subnet)
	smb_enum()
	smtp_enum()
	if zone_transfer_domain != nil
		zone_xfer(zone_transfer_domain)
	end
end
