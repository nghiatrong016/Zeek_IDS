@load base/protocols/conn

export {
    redef enum Notice::Type += {
        Unusual_Conn_Throughput
    };

    global conn_threshold = 1800;
    global throughput_threshold = 33600;
    global conn_log_file = "/opt/zeek/logs/current/conn.log";
    global output_file = open("/opt/zeek/personal_report/scene5/report.log", "a");
}

# Function to preprocess the value
function preprocess_value(value: string): count {
    if ( value in /^.*k$/ ) {
        return to_count(sub(value, /k$/, "")) * 1000;
    }
    if ( value in /^.*m$/ ) {
        return to_count(sub(value, /m$/, "")) * 1000000;
    }
    return to_count(value);
}

# Function to check if values are unusual
function check_values(conn_value: count, throughput_value: count) {
    local conn_threshold_150 = conn_threshold * 150 / 100;
    local throughput_threshold_150 = throughput_threshold * 150 / 100;

    if ( conn_value > conn_threshold_150 && throughput_value > throughput_threshold_150 ) {
        NOTICE([$note=Unusual_Conn_Throughput, 
                $msg=fmt("Unusual values detected - Connection: %d, Throughput: %d", conn_value, throughput_value)]);
        print output_file, fmt("Unusual values detected - Connection: %d, Throughput: %d", conn_value, throughput_value);
    }
}

event zeek_init() {
    # Read the conn.log file
    local conn_log = open(conn_log_file, "r");

    if ( conn_log == nil ) {
        print fmt("Could not open conn.log file: %s", conn_log_file);
        return;
    }

    while ( TRUE ) {
        local line = get_line(conn_log);
        if ( line == nil )
            break;
        
        local fields = split_string(line, /\s+/);
        
        if ( |fields| < 6 )
            continue;

        local conn_value = preprocess_value(fields[3]);
        local throughput_value = preprocess_value(fields[6]);

        check_values(conn_value, throughput_value);
    }

    close(conn_log);
}

event zeek_done() {
    close(output_file);
}
