#!/usr/bin/env python3
"""
SafeOps Engine - Simple Firewall Example

This example demonstrates how to:
1. Connect to SafeOps Engine via gRPC
2. Subscribe to packet metadata stream
3. Analyze packets (domain-based filtering)
4. Apply verdicts (ALLOW, BLOCK, DROP)
5. Use verdict caching for performance

Requirements:
    pip install grpcio grpcio-tools

Usage:
    python simple_firewall.py
"""

import grpc
import sys
import time
from datetime import datetime

# Import generated protobuf files
# Generate with: python -m grpc_tools.protoc -I../../proto --python_out=. --grpc_python_out=. ../../proto/metadata_stream.proto
try:
    import metadata_stream_pb2 as pb
    import metadata_stream_pb2_grpc as pb_grpc
except ImportError:
    print("ERROR: Protobuf files not found!")
    print("Generate them with:")
    print("  python -m grpc_tools.protoc -I../../proto --python_out=. --grpc_python_out=. ../../proto/metadata_stream.proto")
    sys.exit(1)


class SimpleFirewall:
    """
    A simple domain-based firewall using SafeOps Engine
    """

    def __init__(self, grpc_address="127.0.0.1:50051"):
        """
        Initialize firewall and connect to SafeOps Engine

        Args:
            grpc_address: SafeOps Engine gRPC address (default: 127.0.0.1:50051)
        """
        self.grpc_address = grpc_address
        self.client = None
        self.channel = None

        # Firewall rules
        self.blocked_domains = {
            "malware.com",
            "phishing.net",
            "tracker.biz",
            "ads.example.com",
        }

        self.allowed_domains = {
            "google.com",
            "github.com",
            "stackoverflow.com",
        }

        # Statistics
        self.stats = {
            "packets_processed": 0,
            "packets_blocked": 0,
            "packets_allowed": 0,
            "packets_dropped": 0,
        }

    def connect(self):
        """Connect to SafeOps Engine"""
        print(f"🔌 Connecting to SafeOps Engine at {self.grpc_address}...")

        try:
            self.channel = grpc.insecure_channel(self.grpc_address)
            grpc.channel_ready_future(self.channel).result(timeout=5)
            self.client = pb_grpc.MetadataStreamServiceStub(self.channel)
            print("✅ Connected successfully!")
            return True
        except grpc.FutureTimeoutError:
            print(f"❌ Failed to connect to {self.grpc_address}")
            print("   Make sure SafeOps Engine is running!")
            return False

    def get_stats(self):
        """Get SafeOps Engine statistics"""
        try:
            response = self.client.GetStats(pb.StatsRequest())
            print("\n📊 SafeOps Engine Statistics:")
            print(f"   Packets Read:       {response.packets_read:,}")
            print(f"   Packets Written:    {response.packets_written:,}")
            print(f"   Packets Dropped:    {response.packets_dropped:,}")
            print(f"   Active Subscribers: {response.active_subscribers}")
            print(f"   Verdicts Applied:   {response.verdicts_applied:,}")
            print(f"   Cached Verdicts:    {response.cached_verdicts:,}")
        except Exception as e:
            print(f"❌ Failed to get stats: {e}")

    def analyze_packet(self, packet):
        """
        Analyze packet and return verdict

        Args:
            packet: PacketMetadata from SafeOps Engine

        Returns:
            tuple: (verdict_type, reason, cache_ttl)
        """
        # Check if domain is extracted
        if not packet.domain:
            # No domain = allow through (gaming, VoIP, etc.)
            return (pb.VerdictType.ALLOW, "No domain extracted", 0)

        domain = packet.domain.lower()

        # Check blocklist
        if domain in self.blocked_domains:
            return (
                pb.VerdictType.BLOCK,
                f"Domain '{domain}' is on blocklist",
                3600,  # Cache for 1 hour
            )

        # Check if subdomain of blocked domain
        for blocked in self.blocked_domains:
            if domain.endswith("." + blocked):
                return (
                    pb.VerdictType.BLOCK,
                    f"Subdomain of blocked domain '{blocked}'",
                    3600,
                )

        # Allow whitelisted domains
        if domain in self.allowed_domains:
            return (
                pb.VerdictType.ALLOW,
                f"Domain '{domain}' is whitelisted",
                600,  # Cache for 10 minutes
            )

        # Default: allow
        return (pb.VerdictType.ALLOW, "No matching rule", 300)

    def apply_verdict(self, packet, verdict_type, reason, ttl_seconds):
        """
        Send verdict to SafeOps Engine

        Args:
            packet: PacketMetadata
            verdict_type: VerdictType enum
            reason: Human-readable reason
            ttl_seconds: Cache duration
        """
        try:
            response = self.client.ApplyVerdict(
                pb.VerdictRequest(
                    packet_id=packet.packet_id,
                    verdict=verdict_type,
                    reason=reason,
                    rule_id="SIMPLE_FIREWALL_V1",
                    ttl_seconds=ttl_seconds,
                    cache_key=packet.cache_key,
                )
            )

            if response.success:
                # Update stats
                if verdict_type == pb.VerdictType.BLOCK:
                    self.stats["packets_blocked"] += 1
                elif verdict_type == pb.VerdictType.DROP:
                    self.stats["packets_dropped"] += 1
                else:
                    self.stats["packets_allowed"] += 1
            else:
                print(f"⚠️ Verdict failed: {response.message}")

        except Exception as e:
            print(f"❌ Failed to apply verdict: {e}")

    def log_packet(self, packet, verdict_type, reason):
        """
        Log packet decision

        Args:
            packet: PacketMetadata
            verdict_type: VerdictType enum
            reason: Reason for decision
        """
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Color coding
        if verdict_type == pb.VerdictType.BLOCK:
            icon = "🛡️"
            color = "BLOCKED"
        elif verdict_type == pb.VerdictType.DROP:
            icon = "🗑️"
            color = "DROPPED"
        else:
            icon = "✅"
            color = "ALLOWED"

        # Format packet info
        protocol_name = "TCP" if packet.protocol == 6 else "UDP" if packet.protocol == 17 else f"Proto{packet.protocol}"

        # Log
        print(
            f"[{timestamp}] {icon} {color:8} | "
            f"{packet.src_ip:15}:{packet.src_port:5} → "
            f"{packet.dst_ip:15}:{packet.dst_port:5} | "
            f"{protocol_name:3} | "
            f"Domain: {packet.domain:30} | "
            f"{reason}"
        )

    def run(self):
        """Main firewall loop"""
        print("\n" + "=" * 100)
        print("🔥 SafeOps Simple Firewall")
        print("=" * 100)

        # Get initial stats
        self.get_stats()

        print("\n🚀 Starting firewall...")
        print(f"   Blocked domains: {len(self.blocked_domains)}")
        print(f"   Allowed domains: {len(self.allowed_domains)}")
        print("")

        # Subscribe to packet stream
        request = pb.SubscribeRequest(
            subscriber_id="simple-firewall-python-v1",
            filters=["tcp", "udp"],  # Only TCP/UDP (no need for all packets)
        )

        try:
            stream = self.client.StreamMetadata(request)

            print("📡 Monitoring traffic... (Press Ctrl+C to stop)\n")
            print(
                f"{'Time':8} | {'Status':8} | {'Source IP':15} {'Port':5}   {'Destination IP':15} {'Port':5} | {'Proto':3} | {'Domain':30} | {'Reason'}"
            )
            print("-" * 150)

            for packet in stream:
                self.stats["packets_processed"] += 1

                # Analyze packet
                verdict_type, reason, ttl_seconds = self.analyze_packet(packet)

                # Apply verdict
                self.apply_verdict(packet, verdict_type, reason, ttl_seconds)

                # Log decision (only log interesting packets)
                if packet.domain or verdict_type != pb.VerdictType.ALLOW:
                    self.log_packet(packet, verdict_type, reason)

                # Show stats every 100 packets
                if self.stats["packets_processed"] % 100 == 0:
                    print(
                        f"\n📊 Processed: {self.stats['packets_processed']} | "
                        f"Allowed: {self.stats['packets_allowed']} | "
                        f"Blocked: {self.stats['packets_blocked']} | "
                        f"Dropped: {self.stats['packets_dropped']}\n"
                    )

        except KeyboardInterrupt:
            print("\n\n🛑 Stopping firewall...")
        except Exception as e:
            print(f"\n❌ Error: {e}")
        finally:
            self.print_final_stats()

    def print_final_stats(self):
        """Print final statistics"""
        print("\n" + "=" * 100)
        print("📊 Final Statistics")
        print("=" * 100)
        print(f"Packets Processed: {self.stats['packets_processed']:,}")
        print(f"Packets Allowed:   {self.stats['packets_allowed']:,}")
        print(f"Packets Blocked:   {self.stats['packets_blocked']:,}")
        print(f"Packets Dropped:   {self.stats['packets_dropped']:,}")

        if self.stats["packets_processed"] > 0:
            block_rate = (
                self.stats["packets_blocked"] / self.stats["packets_processed"]
            ) * 100
            print(f"Block Rate:        {block_rate:.2f}%")

        print("=" * 100)


def main():
    """Main entry point"""
    firewall = SimpleFirewall()

    # Connect to SafeOps Engine
    if not firewall.connect():
        sys.exit(1)

    # Run firewall
    try:
        firewall.run()
    finally:
        if firewall.channel:
            firewall.channel.close()


if __name__ == "__main__":
    main()
