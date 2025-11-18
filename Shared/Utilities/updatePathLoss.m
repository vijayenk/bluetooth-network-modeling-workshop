
function rxData = updatePathLoss(rxInfo,txData,pathlossCfg)
% Apply path loss and update output signal
rxData = txData;
% Calculate the distance between transmitter and receiver in meters
distance = norm(rxData.TransmitterPosition - rxInfo.Position);
pathloss = bluetoothPathLoss(distance,pathlossCfg);
rxData.Power = rxData.Power-pathloss;                           % In dBm
scale = 10.^(-pathloss/20);
[numSamples,~] = size(rxData.Data);
rxData.Data(1:numSamples,:) = rxData.Data(1:numSamples,:)*scale;
end