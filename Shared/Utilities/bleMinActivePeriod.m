function minActivePeriod = bleMinActivePeriod(payload_bytes, phy_mode)
    % Calculate minimum active period for BLE connection event
    % payload_bytes: application payload in bytes (0-251)
    % num_packets:   number of packets to send
    % phy_mode:      'LE1M', 'LE2M', 'LE500K', 'LE125K'
    
    % Constants
    PREAMBLE_LE1M    = 1;   % bytes
    PREAMBLE_LE2M    = 1;   % bytes
    PREAMBLE_LECODED = 2;   % bytes
    ACCESS_ADDR      = 4;   % bytes
    LL_HEADER        = 2;   % bytes
    CRC              = 3;   % bytes
    IFS              = 150e-6; % 150 microseconds
    TMCES            = 150e-6; % 150 microseconds
    
    % PHY data rates (bits/sec)
    rate.LE1M      = 1e6;
    rate.LE2M      = 2e6;
    rate.LE500K    = 0.5e6;
    rate.LE125K    = 0.125e6;
    num_packets    = 2;
    % Preamble based on PHY
    switch phy_mode
        case 'LE1M'
            preamble_bytes = PREAMBLE_LE1M;
        case 'LE2M'
            preamble_bytes = PREAMBLE_LE2M;
        case {'LE500K', 'LE125K'}
            preamble_bytes = PREAMBLE_LECODED; % LE Coded uses 1-byte preamble before coding
        otherwise
            error('Invalid PHY mode');
    end
    
    % Total bytes per packet
    total_bytes = preamble_bytes + ACCESS_ADDR + LL_HEADER + payload_bytes + CRC;
    total_bits  = total_bytes * 8;
    
    % Packet time (seconds)
    packet_time = total_bits / rate.(phy_mode);
    minActivePeriod = num_packets * packet_time + (num_packets - 1) * IFS + TMCES;
   
end
