use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use safeops_shared::ip_utils::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn bench_ipv4_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPv4 Parsing");
    
    let test_ips = vec![
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "1.1.1.1",
    ];
    
    for ip_str in test_ips {
        group.bench_with_input(BenchmarkId::from_parameter(ip_str), &ip_str, |b, &s| {
            b.iter(|| {
                black_box(s.parse::<Ipv4Addr>())
            });
        });
    }
    
    group.finish();
}

fn bench_ipv6_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("IPv6 Parsing");
    
    let test_ips = vec![
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::1",
        "fe80::1",
        "2001:4860:4860::8888",
    ];
    
    for ip_str in test_ips {
        group.bench_with_input(BenchmarkId::from_parameter(ip_str), &ip_str, |b, &s| {
            b.iter(|| {
                black_box(s.parse::<Ipv6Addr>())
            });
        });
    }
    
    group.finish();
}

fn bench_cidr_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("CIDR Parsing");
    
    let test_cidrs = vec![
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ];
    
    for cidr_str in test_cidrs {
        group.bench_with_input(BenchmarkId::from_parameter(cidr_str), &cidr_str, |b, &s| {
            b.iter(|| {
                black_box(s.parse::<ipnet::IpNet>())
            });
        });
    }
    
    group.finish();
}

fn bench_ip_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("IP Contains Check");
    
    let network: ipnet::Ipv4Net = "192.168.1.0/24".parse().unwrap();
    let ip_in_network: Ipv4Addr = "192.168.1.100".parse().unwrap();
    let ip_outside: Ipv4Addr = "10.0.0.1".parse().unwrap();
    
    group.bench_function("IP in network", |b| {
        b.iter(|| {
            black_box(network.contains(&ip_in_network))
        });
    });
    
    group.bench_function("IP outside network", |b| {
        b.iter(|| {
            black_box(network.contains(&ip_outside))
        });
    });
    
    group.finish();
}

fn bench_ip_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("IP Comparison");
    
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "192.168.1.2".parse().unwrap();
    
    group.bench_function("IP equality", |b| {
        b.iter(|| {
            black_box(ip1 == ip2)
        });
    });
    
    group.bench_function("IP ordering", |b| {
        b.iter(|| {
            black_box(ip1 < ip2)
        });
    });
    
    group.finish();
}

fn bench_cidr_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("CIDR Operations");
    
    let network: ipnet::Ipv4Net = "192.168.0.0/16".parse().unwrap();
    
    group.bench_function("Network address", |b| {
        b.iter(|| {
            black_box(network.network())
        });
    });
    
    group.bench_function("Broadcast address", |b| {
        b.iter(|| {
            black_box(network.broadcast())
        });
    });
    
    group.bench_function("Prefix length", |b| {
        b.iter(|| {
            black_box(network.prefix_len())
        });
    });
    
    group.bench_function("Host count", |b| {
        b.iter(|| {
            black_box(network.hosts().count())
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_ipv4_parsing,
    bench_ipv6_parsing,
    bench_cidr_parsing,
    bench_ip_contains,
    bench_ip_comparison,
    bench_cidr_operations
);

criterion_main!(benches);
