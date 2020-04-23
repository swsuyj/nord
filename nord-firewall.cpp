#include <iostream>
#include <regex>
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>

using namespace std;

//const string fwd = "/usr/bin/firewall-cmd";
const string ipt = "/usr/sbin/iptables";
const string ipt6 = "/usr/sbin/ip6tables";
const string prog_name = "nord-firewall";
const string nord_table = "nord";
const string INPUT_table = "INPUT";
const string OUTPUT_table = "OUTPUT";
const string killswitch_input_table = "nord_input";
const string killswitch_output_table = "nord_output";
const string nord_connection_table = "nord_conn";
const string vpn_interface = "tun0";
const string allowed_states = "RELATED,ESTABLISHED";
const int dns_port = 53;

bool quiet = false;
// Quiet system call prefix
string output_redirect = "1>/dev/null 2>/dev/null";

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

// Usage:  killswitch_ping()
// Before: iptables rules have been set.
// After:  iptables contains rules allowing pinging.
void killswitch_ping() {
	vector<string> cmds;

	cmds.push_back(ipt + " -A " + nord_connection_table +
			" -p icmp " +
			" -j ACCEPT");

	// Apply commands
	apply_rules(cmds);
}

// Usage:  open_by_domain(d)
// Before: d is a domain string.
// After:  Connections are allowed to domain d, over tcp and udp.
void open_by_domain(string domain) {
	vector<string> cmds;

	// Allow dns traffic
	cmds.push_back(ipt + " -A " + nord_connection_table +
			" -p udp " +
			" --dport " + to_string(dns_port) +
			" -j ACCEPT");
	// Allow connection to domain
	cmds.push_back(ipt + " -A " + nord_connection_table +
			" --destination " + domain +
			" -j ACCEPT");

	// Apply commands
	apply_rules(cmds);
}

// Usage:  close_by_ip(ip)
// Before: ip is a string, iptables rules have been set,
//         and a rule possibly exists allowing connections to ip.
// After:  Rules (not multiples) allowing connections to
//         ip have been removed.
void close_by_ip(string ip) {
	log("Closing firewall for ip address " + ip);

	vector<string> cmds;
	cmds.push_back(ipt + " -F " + nord_connection_table);

	apply_rules(cmds);
}
// Aliases
void killswitch_disconnect() { close_by_ip(""); }

// Usage:  open_by_ip(ip, proto, port)
// Before: ip is a string, proto is 'udp' or 'tcp',
//         port is a port to use, iptables rules have been set.
// After:  Rules exist in iptables which allow
//         connections to ip.
void open_by_ip(string ip, string protocol, int port) {
	log("Opening firewall for ip address " + ip);

	// Disconnecting first to ensure no redundancy,
	// and unused rules.
	killswitch_disconnect();

	vector<string> cmds;
	cmds.push_back(ipt + " -F " + nord_connection_table);
	cmds.push_back(ipt + " -A " + nord_connection_table +
			" -p " + protocol +
			" --dport " + to_string(port) +
			" --destination " + ip +
			" -j ACCEPT");

	apply_rules(cmds);
}

// Usage:  killswitch_off()
// Before: iptables rules contain rules allowing only
//         connections over vpn.
// After:  Connections are allowed as normal.
void killswitch_off() {
	vector<string> cmds;
	cmds.push_back(ipt + " -D INPUT -j " + killswitch_input_table);
	cmds.push_back(ipt + " -D OUTPUT -j " + killswitch_output_table);

	// Apply commands
	apply_rules(cmds);
}

// Usage:  killswitch_on()
// Before: iptables has been set up.
// After:  iptables rules contain rules allowing only
//         connections over vpn.
void killswitch_on() {
	// Turning killswitch first off ensures that
	// multiples of the following rules are not present.
	log("Turning killswitch off before turning on, even if off");
	killswitch_off();
	log("Turning killswitch on");
	vector<string> cmds;
	cmds.push_back(ipt + " -A INPUT -j " + killswitch_input_table);
	cmds.push_back(ipt + " -A OUTPUT -j " + killswitch_output_table);

	// Apply commands
	apply_rules(cmds);
}

// Usage:  killswitch_setup()
// Before: iptables is installed and active.
// After:  iptables chains exist which only allow vpn connections.
void killswitch_setup() {
	vector<string> cmds;

	// Create the necessary tables
	cmds.push_back(ipt + " -N " + nord_table);
	cmds.push_back(ipt + " -N " + killswitch_input_table);
	cmds.push_back(ipt + " -N " + killswitch_output_table);
	cmds.push_back(ipt + " -N " + nord_connection_table);

	// Clear the new tables, in case they existed
	cmds.push_back(ipt + " -F " + nord_table);
	cmds.push_back(ipt + " -F " + killswitch_input_table);
	cmds.push_back(ipt + " -F " + killswitch_output_table);
	cmds.push_back(ipt + " -F " + nord_connection_table);

	// Link the tables
	cmds.push_back(ipt + " -A " + killswitch_input_table +
			" -j " + nord_table);
	cmds.push_back(ipt + " -A " + killswitch_output_table +
			" -j " + nord_table);
	cmds.push_back(ipt + " -A " + nord_table +
			" -j " + nord_connection_table);
//	cmds.push_back(ipt + " -A " + input_table +
//			" -j " + killswitch_input_table);
//	cmds.push_back(ipt + " -A " + output_table +
//			" -j " + killswitch_output_table);

	// Allow forwards
	cmds.push_back(ipt + " -A " + killswitch_input_table +
			" -i lo -j ACCEPT");
	cmds.push_back(ipt + " -A " + killswitch_output_table +
			" -o lo -j ACCEPT");

	// Allow all vpn access
	cmds.push_back(ipt + " -A " + killswitch_output_table +
			" -o " + vpn_interface +
			" -j ACCEPT");

	// Allow established connections
	cmds.push_back(ipt + " -A " + killswitch_input_table +
			" -m state --state " + allowed_states +
			" -j ACCEPT");

	// Block input and output by default
	cmds.push_back(ipt + " -A " + killswitch_input_table +
			" -j DROP");
	cmds.push_back(ipt + " -A " + killswitch_output_table +
			" -j DROP");

	// Block all ipv6
	cmds.push_back(ipt6 + " -A " + INPUT_table +
			" -j DROP");
	cmds.push_back(ipt6 + " -A " + OUTPUT_table +
			" -j DROP");

	// Apply all rules
	apply_rules(cmds);
}

// Usage:  killswitch_teardown()
// Before: Killswitch has been set up previously.
// After:  iptables no longer contains chains for our killswitch.
void killswitch_teardown() {
	vector<string> cmds;

	// Remove linkis from INPUPT and OUTPUT to our tables.
	killswitch_off();

	// Flush all the tables we created
	cmds.push_back(ipt + " -F " + nord_table);
	cmds.push_back(ipt + " -F " + killswitch_input_table);
	cmds.push_back(ipt + " -F " + killswitch_output_table);
	cmds.push_back(ipt + " -F " + nord_connection_table);

	// Then delete all the tables
	cmds.push_back(ipt + " -X " + nord_table);
	cmds.push_back(ipt + " -X " + killswitch_input_table);
	cmds.push_back(ipt + " -X " + killswitch_output_table);
	cmds.push_back(ipt + " -X " + nord_connection_table);

	// Apply all rules
	apply_rules(cmds);
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
			throw std::invalid_argument("Incorrect killswitch argument");
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
