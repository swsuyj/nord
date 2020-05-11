#include <iostream>
#include <regex>
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>

using namespace std;

// Programs & other
//const string ipt = "/usr/sbin/iptables";
//const string ipt6 = "/usr/sbin/ip6tables";
const string echo = "/usr/bin/echo ";
const string fwd = "/usr/bin/firewall-cmd";
const string fwdd = "/usr/bin/firewall-cmd --direct";
const string fwdq = "/usr/bin/firewall-cmd -q";
const string fwdqd = "/usr/bin/firewall-cmd -q --direct";
const string prog_name = "nord-firewall";
const string vpn_interface = "tun0";
const string allowed_states = "RELATED,ESTABLISHED";
const int dns_port = 53;

// Nord chains
const string nord4_conn = " ipv4 filter nord_conn ";
const string nord6_conn = " ipv6 filter nord_conn ";
const string nord4_outbound = " ipv4 filter nord_outbound ";
const string nord4_inbound = " ipv4 filter nord_inbound ";
const string nord6_outbound = " ipv6 filter nord_outbound ";
const string nord6_inbound = " ipv6 filter nord_inbound ";
const string out4 = " ipv4 filter OUTPUT ";
const string in4 = " ipv4 filter INPUT ";
const string out6 = " ipv6 filter OUTPUT ";
const string in6 = " ipv6 filter INPUT ";

// Common firewalld comands/strings
const string add_rule = " --add-rule ";
const string remove_rule = " --remove-rule ";
const string permanent_rule = " --permanent ";
const string protocol_rule = " -p ";
const string jump_rule = " -j ";
const string destination_rule = " --destination ";
const string icmp_rule = " -p icmp ";
const string udp_rule = " -p udp ";
const string tcp_rule = " -p tcp ";
const string port_rule = " --dport ";
const string accept_rule = " -j ACCEPT ";
const string drop_rule = " -j DROP ";
const string killswitch_in_rule = " -j nord_inbound ";
const string killswitch_out_rule = " -j nord_outbound ";

// Priority levels for firewalld
const string connection_priority = " 199 ";
const string killswitch_priority = " 999 ";
const string highest_priority = " 0 ";
const string temp_priority = " 10 ";
const string high_priority = " 100 ";
const string medium_priority = " 200 ";
const string low_priority = " 300 ";
const string lowest_priority = " 1000 ";

bool quiet = false;
string quiet_flag = " -q ";
// Quiet system call prefix
string output_redirect = "1>/dev/null 2>/dev/null ";

void log(string s) {
	if (quiet) return;
	cout << prog_name << " -- " << s << '\n';
}

void apply_rules(vector<string> cmds) {
	// Apply commands
	for (string cmd : cmds) {
		log("Applying: " + cmd);
		system((output_redirect + cmd).c_str());
	}
}

// Usage:  clear_chain(chain,p)
// Before: chain is set up, p is a boolean
// After:  chain contains no rules, similar to -F in iptables,
//         if p is true, the permanent version of chain has been
//         cleared.
void clear_chain(string chain, bool permanent) {
	log("Clearing chain" + chain);

	while (chain.size() > 0 && chain[0] == ' ') {
		log("Removing leading whitespace in chain name");
		chain = &chain[1];
	}
	string permanent_flag = permanent? " --permanent ":"";
	log((string)"debug: " + "permanent_flag: " + permanent_flag);
	log((string)"debug: " + "permanent argument: " + to_string(permanent));

	string fw = fwdqd + permanent_flag;
	vector<string> cmds;
	// Bash code to delete firewalld rules of chain
	// Note that we can't use the '-q' flag
	cmds.push_back("rules=$(" +
			fwdd +
			" --get-all-rules " +
			" | grep -i '" +
			chain +
			"'); " +
			"cmd=''; " +
			"for s in ${rules[@]}; do " +
				"if [[ $s == ipv4 || $s == ipv6 ]]; then " +
					"[[ -n $cmd ]] && " +
				fw +
				remove_rule +
				" $cmd; " +
					"cmd=$s; " +
				"else cmd+=\" $s\"; " +
				"fi; " +
			"done; " +
			"[[ -n $cmd ]] && " +
			fw +
			remove_rule +
			" $cmd;");

	apply_rules(cmds);
}
// Aliases
void clear_chain(string chain) {
	clear_chain(chain,false);
}

// Usage:  killswitch_disconnect()
// Before: Kill switch has been set up and is active.
// After:  Kill switch has been disconnected.
void killswitch_disconnect() {
	clear_chain(nord4_conn);
	clear_chain(nord6_conn);
}

// Usage:  killswitch_ping()
// Before: Firewall rules have been set.
// After:  Firewall contains rules allowing pinging.
void killswitch_ping() {
	log("Opening firewall for pinging");
	vector<string> cmds;

	cmds.push_back(fwdqd +
			add_rule +
			nord4_conn +
			medium_priority +
			icmp_rule +
			accept_rule);

	// Apply commands
	apply_rules(cmds);
}

// Usage:  open_by_domain(d)
// Before: d is a domain string.
// After:  Connections are allowed to domain d, over tcp and udp.
void open_by_domain(string domain) {
	log("Opening firewall for domain " + domain);
	vector<string> cmds;

	// Rule for allowing dns traffic
	string dns_rule = nord4_conn + medium_priority +
		udp_rule + port_rule + to_string(dns_port) + accept_rule;

	// Allow dns traffic
	cmds.push_back(fwdqd +
			add_rule +
			dns_rule);
	// Allow connection to domain
	cmds.push_back(fwdqd +
			add_rule +
			nord4_conn +
			medium_priority +
			destination_rule +
			domain +
			accept_rule);
	// WARNING! DNS traffic to any domain is allowed,
	// until nord_conn is cleared!

	// Apply commands
	apply_rules(cmds);
}

// Usage:  close_by_ip(ip)
// Before: ip is a string, firewall rules have been set,
//         and a rule possibly exists allowing connections to ip.
// After:  Rules (not multiples) allowing connections to
//         ip have been removed.
void close_by_ip(string ip) {
	log("Closing firewall for ip address " + ip);

	vector<string> cmds;
	cmds.push_back(fwdqd +
			remove_rule +
			nord4_outbound +
			connection_priority +
			destination_rule +
			ip);

	apply_rules(cmds);
}

// Usage:  open_by_ip(ip, proto, port)
// Before: ip is a string, proto is 'udp' or 'tcp',
//         port is a port to use, firewall rules have been set.
// After:  Rules exist in firewall which allow
//         connections to ip.
void open_by_ip(string ip, string protocol, int port) {
	log("Opening firewall for ip address " + ip);

	// Clear past connections
	clear_chain(nord4_conn);

	vector<string> cmds;
	cmds.push_back(fwdqd +
			add_rule +
			nord4_conn +
			connection_priority +
			protocol_rule +
			protocol +
			port_rule +
			to_string(port) +
			destination_rule +
			ip +
			accept_rule);

	apply_rules(cmds);
}

// Usage:  killswitch_off()
// Before: Firewall rules contain rules allowing only
//         connections over vpn.
// After:  Connections are allowed as normal.
void killswitch_off() {
	log("Turning kill switch off");
	vector<string> cmds;
	// ipv4
	cmds.push_back(fwdqd +
			permanent_rule +
			remove_rule +
			in4 +
			killswitch_priority +
			killswitch_in_rule);
	cmds.push_back(fwdqd +
			permanent_rule +
			remove_rule +
			out4 +
			killswitch_priority +
			killswitch_out_rule);
	// ipv6
	cmds.push_back(fwdqd +
			permanent_rule +
			remove_rule +
			in6 +
			killswitch_priority +
			killswitch_in_rule);
	cmds.push_back(fwdqd +
			permanent_rule +
			remove_rule +
			out6 +
			killswitch_priority +
			killswitch_out_rule);
	cmds.push_back(fwdq +
			" --reload ");

	// Apply commands
	apply_rules(cmds);
}

// Usage:  killswitch_on()
// Before: Firewall has been set up.
// After:  Firewall rules contain rules allowing only
//         connections over vpn.
void killswitch_on() {
	// Turning kill switch first off ensures that
	// multiples of the following rules are not present.
	log("Turning kill switch off before turning on, even if off");
	killswitch_off();
	log("Turning kill switch on");
	vector<string> cmds;
	// ipv4
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			in4 +
			killswitch_priority +
			killswitch_in_rule);
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			out4 +
			killswitch_priority +
			killswitch_out_rule);
	// ipv6
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			in6 +
			killswitch_priority +
			killswitch_in_rule);
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			out6 +
			killswitch_priority +
			killswitch_out_rule);
	cmds.push_back(fwdq +
			" --reload ");

	// Apply commands
	apply_rules(cmds);
}

// Usage:  killswitch_setup()
// Before: Firewall is installed and active.
// After:  Firewall chains exist which only allow vpn connections.
void killswitch_setup() {
	log("Setting up kill switch");
	vector<string> cmds;

	cmds.push_back(echo + "Settinp up chains");
	// Create the necessary chains
	cmds.push_back(fwdqd +
			permanent_rule +
			" --add-chain " +
			nord4_inbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --add-chain " +
			nord4_outbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --add-chain " +
			nord6_inbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --add-chain " +
			nord6_outbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --add-chain " +
			nord4_conn);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --add-chain " +
			nord6_conn);

	cmds.push_back(echo + "Clearing chains, in case they existed");
	// Clear the new chains, in case they existed
	clear_chain(nord4_inbound, true);
	clear_chain(nord4_outbound, true);
	clear_chain(nord6_inbound, true);
	clear_chain(nord6_outbound, true);
	clear_chain(nord4_conn, true);
	clear_chain(nord6_conn, true);

	cmds.push_back(echo + "Linking the chains");
	// Link the chains
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_outbound +
			killswitch_priority +
			" -j nord_conn ");
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord6_outbound +
			killswitch_priority +
			" -j nord_conn ");

	cmds.push_back(echo + "Setting VPN rules"); // allow/disallow certain traffic
	// Allow forwards
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_inbound +
			killswitch_priority +
			" -i lo -j ACCEPT");
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_outbound +
			killswitch_priority +
			" -o lo -j ACCEPT");
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord6_inbound +
			killswitch_priority +
			" -i lo -j ACCEPT");
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord6_outbound +
			killswitch_priority +
			" -o lo -j ACCEPT");

	// Allow all vpn access
	// Only on ipv4
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_outbound +
			killswitch_priority +
			" -o " +
			vpn_interface +
			accept_rule);

	// Allow established connections
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_inbound +
			killswitch_priority +
			" -m state --state " +
			allowed_states +
			accept_rule);

	// Block input and output by default
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_inbound +
			lowest_priority +
			drop_rule);
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord4_outbound +
			lowest_priority +
			drop_rule);

	// Block all ipv6
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord6_inbound +
			lowest_priority +
			drop_rule);
	cmds.push_back(fwdqd +
			permanent_rule +
			add_rule +
			nord6_outbound +
			lowest_priority +
			drop_rule);

	// Reload firewall to enable permanent ruleset
	cmds.push_back(fwdq +
			" --reload");

	log("Applying kill switch setup rules");
	// Apply all rules
	apply_rules(cmds);
	log("Kill switch has been set up");
}

// Usage:  killswitch_teardown()
// Before: Kill switch has been set up previously.
// After:  Firewall no longer contains chains for our kill switch.
void killswitch_teardown() {
	log("Tearing kill switch down");
	vector<string> cmds;

	// Remove linkis from INPUPT and OUTPUT to our chains.
	killswitch_off();

	// Flush all the chains we created
	clear_chain(nord4_inbound, true);
	clear_chain(nord4_outbound, true);
	clear_chain(nord6_inbound, true);
	clear_chain(nord6_outbound, true);
	clear_chain(nord4_conn, true);
	clear_chain(nord6_conn, true);

	// Then delete all the chains
	cmds.push_back(fwdqd +
			permanent_rule +
			" --remove-chain " +
			nord4_inbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --remove-chain " +
			nord4_outbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --remove-chain " +
			nord6_inbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --remove-chain " +
			nord6_outbound);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --remove-chain " +
			nord4_conn);
	cmds.push_back(fwdqd +
			permanent_rule +
			" --remove-chain " +
			nord6_conn);

	// Finally reaload firewall to clear non-permanent rules
	cmds.push_back(fwdq +
			" --reload ");

	// Apply all rules
	apply_rules(cmds);
	log("Kill switch has been removed");
}

int main(int argc, char* argv[]) {
	// Store command line argument and uid
	int uid = getuid();
	int euid = geteuid();
	string s;
	if (argc > 1) {
		s = argv[1];
		if (s == "-q") {
			quiet = true;
			if (argc > 2) {
				argc--;
				argv = &argv[1];
				s = argv[1];
			}
			else return 1;
		}
		else {
			output_redirect = "";
		}
	}
	else return 1;

	if (s == "killswitch") {
		string ks_arg; // Kill Switch ARGument
		if (argc > 2) ks_arg = argv[2];

		// Switch statemnt for string
		       if(ks_arg == "on") {
			setuid(0); seteuid(0);
			killswitch_on();
			setuid(euid); seteuid(uid);
		} else if(ks_arg == "off") {
			setuid(0); seteuid(0);
			killswitch_off();
			seteuid(euid); setuid(uid);
		} else if(ks_arg == "setup") {
			setuid(0); seteuid(0);
			killswitch_setup();
			seteuid(euid); setuid(uid);
		} else if(ks_arg == "teardown") {
			setuid(0); seteuid(0);
			killswitch_teardown();
			seteuid(euid); setuid(uid);
		} else if(ks_arg == "disconnect") {
			setuid(0); seteuid(0);
			killswitch_disconnect();
			seteuid(euid); setuid(uid);
		} else if(ks_arg == "ping") {
			setuid(0); seteuid(0);
			killswitch_ping();
			seteuid(euid); setuid(uid);
		} else {
			throw std::invalid_argument("Incorrect kill switch argument");
		}
		return 0;
	}

	// Assuming command line argument is an ip hereafter
	regex ip_regex("^(((\\d){1,3}\\.){3}\\d{1,3})$"); // ipv4 regex
	regex domain_regex("^[\\w.-]+\\.\\w{2,10}$");
	smatch m; // Regex match object
	if (regex_match(s, m, ip_regex)) {
		string ip = m[0].str(); // Matches are stored in m[0..n]

		// Validate protocol and port input
		string protocol;
		int port;
		if (argc > 3) {
			protocol = argv[2];
			port = stoi(argv[3]);
			log("Accepting protocol " + protocol + " and port " + to_string(port));
		} else {
			throw std::out_of_range("Incorrect number of arguments");
		}

		// Set-UID critical part
		setuid(0); seteuid(0);
		open_by_ip(s, protocol, port);
		seteuid(euid); setuid(uid);
	} else if (regex_match(s, m, domain_regex)) {
			string domain = m[0].str();
			setuid(0); seteuid(0);
			open_by_domain(domain);
			seteuid(euid); setuid(uid);
	} else {
		log("That was not a valid ip address.");
		log("Your entered text: " + s);
	}
}
