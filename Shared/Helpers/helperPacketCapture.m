classdef helperPacketCapture < handle
    %helperPacketCapture Capture Bluetooth LE packets to PCAP or PCAPNG
    %file
    %
    %   OBJ = helperPacketCapture(BluetoothNodes) creates a default
    %   Bluetooth(R) low energy (LE) packet capture object.
    %
    %   OBJ = helperPacketCapture(BluetoothNodes,fileExtension)
    %   additionally specifies the file extension of the packet capture
    %   (PCAP) or packet capture next generation (PCAPNG) file.
    %
    %   BluetoothNodes is the Bluetooth LE nodes to capature packets
    %   specified as a normal array or a cell array having scalar objects
    %   of type bluetoothLENode.
    %
    %   FileExtension is the extension of the packet capture file,
    %   specified as "pcap" "or "pcapng". By default packets are captured
    %   in "pcap" file.
    %
    %   helperPacketCapture properties (read-only):
    %
    %   PCAPObjs       - PCAP file writer for bluetoothLENode
    %   BluetoothNodes - Configured Bluetooth LE nodes

    %   Copyright 2022-2023 The MathWorks, Inc.

    properties (SetAccess=private)
        %PCAPObjs PCAP file writer for bluetoothLENode
        %   PCAPObjs is a cell array of PCAP file writer objects that
        %   writes Bluetooth LE packets to the PCAP or PCAPNG file. The
        %   packets are written to the file from the
        %   PacketTransmissionStarted and PacketReceptionEnded events of
        %   the bluetoothLENode object. The value is an object of type
        %   blePCAPWriter.
        PCAPObjs

        %BluetoothNodes Configured Bluetooth LE nodes in the network
        %   BluetoothNodes is a cell array of the configured Bluetooth LE
        %   nodes in the network. The value of the cell arrays is an object
        %   of type bluetootLENode.
        BluetoothNodes
    end

    methods
        function obj = helperPacketCapture(bluetoothNodes,fileExtension)
            %Constructor

            % Check for number of input arguments
            narginchk(1,2);

            if nargin==1
                % Default file extension is pcap
                fileExtension = "pcap";
            else
                % Validate the specified file extension
                validatestring(fileExtension,{'pcap','pcapng'},mfilename,"fileExtension");
            end

            % If the input nodes is a normal array change to cell array
            if isobject(bluetoothNodes)
                bluetoothNodes = num2cell(bluetoothNodes);
                obj.BluetoothNodes = bluetoothNodes;
            else
                obj.BluetoothNodes = bluetoothNodes;
            end

            % Validate for Bluetooth LE node and add listeners based on the
            % type of the node
            for idx = 1:numel(bluetoothNodes)
                validateattributes(bluetoothNodes{idx}, "bluetoothLENode", {'scalar'});

                % PCAP file name is by the format:
                % <NodeName_NodeID_yyyyMMdd_HHmmss>
                pcapFileName = strjoin([bluetoothNodes{idx}.Name "_" bluetoothNodes{idx}.ID "_" char(datetime('now','Format','yyyyMMdd_HHmmss'))],"");

                obj.PCAPObjs{idx} = blePCAPWriter('FileName',pcapFileName, 'PhyHeaderPresent', true, ...
                    'FileExtension', fileExtension, 'ByteOrder', 'little-endian');
                addListeners(obj,bluetoothNodes{idx});
            end
        end
    end

    methods (Access = private)
        function captureLEPackets(obj,nodeObj,eventData)
            %captureLEPackets Captures and writes Bluetooth LE packets to
            %the corresponding PCAP object

            % Find the index of the PCAP object for the incoming node
            % object
            for pcapIdx = 1:numel(obj.BluetoothNodes)
                if nodeObj.ID==obj.BluetoothNodes{pcapIdx}.ID
                    break;
                end
            end

            % Get the received packet data
            packetData = eventData.Data;

            % Get the PDU transmitted or received
            llDataPDU = packetData.PDU;

            % Convert the access address of the packet in binary
            if isempty(packetData.AccessAddress)
                connAccessAddress = zeros(32,1);
            else
                connAccessAddress = int2bit(hex2dec(packetData.AccessAddress),32,false);
            end

            role = nodeObj.Role;
            eventTransmission = strcmp(eventData.EventName,'PacketTransmissionStarted');

            % Create the header
            rfChannels = [37 0:10 38 11:36 39]; % List of LE RF channels
            rfChannel = int2bit(find(rfChannels==packetData.ChannelIndex)-1,8,false);
            if eventTransmission
                signalPowerBits = double(int2bit(int8(eventData.Data.TransmittedPower),8,false));
                noisePowerBits = int2bit(0,8,false);
            else
                signalPowerBits = double(int2bit(int8(eventData.Data.ReceivedPower),8,false));
                noisePower = eventData.Data.ReceivedPower-real(eventData.Data.SINR);
                noisePowerBits = double(int2bit(int8(noisePower),8,false));
            end

            accessAddressOffenses = int2bit(0,8,false);

            % Create the flags
            flags = zeros(16,1);
            flags(1) = 1; % Whitened
            flags(2) = 1; % Signal power field
            flags(3) = 1; % Noise Power field
            flags(4) = 0; % LE Packet is decrypted
            flags(5) = 1; % Reference Access Address field has valid data
            flags(6) = 0; % Access Address Offenses has invalid data
            flags(7) = 0; % RF Channel is not subject to aliasing

            if (strcmp(role,"central") && eventTransmission) || ...
                    (strcmp(role,"peripheral") && ~eventTransmission)
                if nodeObj.NumCISConnections>0 && any(strcmp(eventData.Data.AccessAddress,string({nodeObj.CISConfig.AccessAddress})))
                    flags(8:10) = [0;0;1]; % CIS Data from Central to Peripheral
                end
                if any(strcmp(eventData.Data.AccessAddress,[nodeObj.ConnectionConfig.AccessAddress]))
                    flags(8:10) = [0;1;0]; % ACL Data from Central to Peripheral
                end
            elseif (strcmp(role,"central") && ~eventTransmission) || ...
                    (strcmp(role,"peripheral") && eventTransmission)
                if nodeObj.NumCISConnections>0 && any(strcmp(eventData.Data.AccessAddress,string({nodeObj.CISConfig.AccessAddress})))
                    flags(8:10) = [1;0;1]; % CIS Data from Peripheral to Central
                end
                if any(strcmp(eventData.Data.AccessAddress,[nodeObj.ConnectionConfig.AccessAddress]))
                    flags(8:10) = [1;1;0]; % ACL Data from Peripheral to Central
                end
            elseif strcmp(role,"synchronized-receiver") || strcmp(role,"isochronous-broadcaster")
                flags(8:10) = [0;1;1];
            elseif strcmp(role,"observer") || strcmp(role,"broadcaster")
                if nodeObj.NumPeriodicAdvs>0
                    flags(8:10) = [1;0;0];
                end
            end
            flags(11) = 1; % CRC Checked
            if eventTransmission || (~eventTransmission && eventData.Data.SuccessStatus)
                flags(12) = 1; % CRC checked and passed
            end
            flags(13:14) = 0; % MIC portion not checked
            if strcmp(role,"observer") || strcmp(role,"broadcaster")
                if nodeObj.NumPeriodicAdvs>0
                    flags(13:14) = [0;1]; % For AUX_SYNC_IND
                end
            end
            CI = [];
            switch (eventData.Data.PHYMode)
                case 'LE1M'
                    flags(15:16) = [0;0];
                case 'LE2M'
                    flags(15:16) = [1;0];
                case {'LE125K','LE500K'}
                    flags(15:16) = [0;1];
                    CI = zeros(8,1);
                    if strcmp(eventData.Data.PHYMode, 'LE500K')
                        CI(7:8) = [1;0];
                    end
                otherwise
                    flags(15:16) = [1;1];
            end

            packetHeader = [rfChannel;signalPowerBits;noisePowerBits;accessAddressOffenses;connAccessAddress;flags];

            % Create the Bluetooth LE packet for writing to PCAP
            if ~isempty(CI)
                packetWithoutPreamble = ([connAccessAddress;CI;llDataPDU]);
            else
                packetWithoutPreamble = ([connAccessAddress;llDataPDU]);
            end

            % Calculate the timestamp of the packet transmitted or received
            % in microseconds
            timestamp = round(packetData.CurrentTime*1e6);

            % Write the Bluetooth LE Packet
            write(obj.PCAPObjs{pcapIdx},packetWithoutPreamble,timestamp,'PacketFormat','bits','PhyHeader',packetHeader,'PhyHeaderFormat','bits');
        end

        function addListeners(obj,node)
            %addListeners Adds listeners at the Bluetooth LE nodes for the
            %PacketTransmissionStarted and PacketReceptionEnded events

            funcHandle = @(nodeobj,eventdata) captureLEPackets(obj,nodeobj,eventdata);
            addlistener(node,"PacketTransmissionStarted",funcHandle);
            addlistener(node,"PacketReceptionEnded",funcHandle);
        end
    end
end
