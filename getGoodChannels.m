function goodChannels = getGoodChannels(userData)

wlanBand = userData{1}.Nodes{4}.DeviceConfig.BandAndChannel(1);
wlanChannel = userData{1}.Nodes{4}.DeviceConfig.BandAndChannel(2);
wlanBW = userData{1}.Nodes{4}.DeviceConfig.ChannelBandwidth;
wlanCenter  = wlanChannelFrequency(wlanChannel,wlanBand);
numBLE = 37;   % BLE Data channels
bleBW  = 2e6;    % MHz
overlapResults = zeros(1, numBLE);
wlanBand = [wlanCenter - wlanBW/2, wlanCenter + wlanBW/2];
BleDataChannelFrequencies = [2404:2:2424 2428:2:2478]*1e6;
for ch = 0:numBLE-1
    bleFreq =BleDataChannelFrequencies(ch+1);  % center frequency in MHz
    bleBand = [bleFreq - bleBW/2, bleFreq + bleBW/2];
    % overlap calculation
    overlap = max(0, min(bleBand(2), wlanBand(2)) - max(bleBand(1), wlanBand(1)));
    overlapResults(ch+1) = overlap;
end
goodChannels = find(overlapResults == 0) -1;
goodChannels = goodChannels(goodChannels <= 36);
end