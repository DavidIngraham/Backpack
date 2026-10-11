// Link MAVLink.cpp separately: parser reset must affect that translation unit.
#include <Arduino.h>
#include "MAVLink.h"
#include <cassert>
#include <cstdio>

TestSerial Serial;

static std::vector<uint8_t> heartbeat(bool v1)
{
    mavlink_get_channel_status(MAVLINK_COMM_0)->flags =
        v1 ? MAVLINK_STATUS_FLAG_OUT_MAVLINK1 : 0;
    mavlink_message_t message;
    mavlink_msg_heartbeat_pack(42, 1, &message, MAV_TYPE_FIXED_WING,
                              MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0, MAV_STATE_STANDBY);
    std::vector<uint8_t> bytes(MAVLINK_MAX_PACKET_LEN);
    bytes.resize(mavlink_msg_to_send_buffer(bytes.data(), &message));
    return bytes;
}

int main()
{
    MAVLink bridge;
    assert(bridge.GetMavlinkStats()->packets_uplink == 0);
    auto v1 = heartbeat(true);
    auto v2 = heartbeat(false);
    assert(v1[0] == MAVLINK_STX_MAVLINK1 && v2[0] == MAVLINK_STX);

    // WebSocket and UDP may interleave partial packets without sharing state.
    bridge.ProcessMAVLinkFromGCS(v2.data(), 5, MAVLINK_COMM_2);
    bridge.ProcessMAVLinkFromGCS(v1.data(), 4);
    assert(Serial.bytes.empty());
    bridge.ProcessMAVLinkFromGCS(v2.data() + 5, v2.size() - 5, MAVLINK_COMM_2);
    assert(Serial.bytes == v2);
    Serial.bytes.clear();
    bridge.ProcessMAVLinkFromGCS(v1.data() + 4, v1.size() - 4);
    assert(Serial.bytes == v1);

    // A reconnect must discard a partial packet in the production parser.
    Serial.bytes.clear();
    bridge.ProcessMAVLinkFromGCS(v2.data(), 5, MAVLINK_COMM_2);
    bridge.ResetGCSParser(MAVLINK_COMM_2);
    bridge.ProcessMAVLinkFromGCS(v2.data() + 5, v2.size() - 5, MAVLINK_COMM_2);
    assert(Serial.bytes.empty());
    bridge.ProcessMAVLinkFromGCS(v2.data(), v2.size(), MAVLINK_COMM_2);
    assert(Serial.bytes == v2);

    // A single binary message can hold many MAVLink frames of either version.
    auto combined = v1;
    combined.insert(combined.end(), v2.begin(), v2.end());
    Serial.bytes.clear();
    bridge.ProcessMAVLinkFromGCS(combined.data(), combined.size(), MAVLINK_COMM_2);
    assert(Serial.bytes == combined);
    assert(bridge.GetMavlinkStats()->packets_uplink == 5);

    // Downlink frames survive parsing and serialization byte-for-byte.
    for (auto byte : combined) bridge.ProcessMAVLinkFromTX(byte);
    assert(bridge.GetQueuedMsgCount() == 2);
    for (unsigned i = 0; i < 2; ++i)
    {
        uint8_t packet[MAVLINK_MAX_PACKET_LEN];
        auto length = mavlink_msg_to_send_buffer(packet, &bridge.GetQueuedMsgs()[i]);
        assert(std::vector<uint8_t>(packet, packet + length) == (i ? v2 : v1));
    }
    puts("Real MAVLink v1/v2 transport tests passed");
}
