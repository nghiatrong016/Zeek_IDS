module DDosAttacks;

@load base/protocols/dns
@load base/frameworks/notice

redef enum Notice::Type += {
    DNSDDoSAttack
};

const dns_threshold: count = 100;  # Adjust this threshold as needed
const time_window: interval = 60sec;

global dns_counter: table[addr] of count &default=0;

function generate_ddos_notice(c: connection, query: string) {
    NOTICE([$note=DNSDDoSAttack,
            $msg=fmt("Possible DNS DDoS Attack detected from %s", c$id$orig_h),
            $conn=c,
            $uid=c$uid]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    dns_counter[c$id$orig_h] += 1;

    if (dns_counter[c$id$orig_h] > dns_threshold) {
        generate_ddos_notice(c, query);
        dns_counter[c$id$orig_h] = 0;  # Reset the counter to avoid generating multiple notices for the same host
    }
}

event timer() {
    for (ip in dns_counter) {
        if (dns_counter[ip] > 0) {
            dns_counter[ip] -= 1;
        }
    }
}
