use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use safeops_shared::hash_utils::*;
use ahash::AHasher;
use xxhash_rust::xxh3::Xxh3;
use std::hash::{Hash, Hasher};

const TEST_DATA_SIZES: &[usize] = &[16, 64, 256, 1024, 4096, 16384];

fn bench_ahash(c: &mut Criterion) {
    let mut group = c.benchmark_group("AHash");
    
    for &size in TEST_DATA_SIZES {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = AHasher::default();
                data.hash(&mut hasher);
                black_box(hasher.finish())
            });
        });
    }
    
    group.finish();
}

fn bench_xxh3(c: &mut Criterion) {
    let mut group = c.benchmark_group("XXH3");
    
    for &size in TEST_DATA_SIZES {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let mut hasher = Xxh3::default();
                hasher.write(data);
                black_box(hasher.finish())
            });
        });
    }
    
    group.finish();
}

fn bench_hash_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash Algorithm Comparison");
    
    let packet_size = 1500; // Standard MTU
    let packet_data: Vec<u8> = (0..packet_size).map(|i| (i % 256) as u8).collect();
    
    group.throughput(Throughput::Bytes(packet_size as u64));
    
    group.bench_function("AHash 1500 bytes", |b| {
        b.iter(|| {
            let mut hasher = AHasher::default();
            packet_data.hash(&mut hasher);
            black_box(hasher.finish())
        });
    });
    
    group.bench_function("XXH3 1500 bytes", |b| {
        b.iter(|| {
            let mut hasher = Xxh3::default();
            hasher.write(&packet_data);
            black_box(hasher.finish())
        });
    });
    
    group.finish();
}

fn bench_connection_tuple_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Connection Tuple Hash");
    
    // Simulate connection 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol
    #[derive(Hash)]
    struct ConnectionTuple {
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    }
    
    let tuple = ConnectionTuple {
        src_ip: 0xC0A80101,    // 192.168.1.1
        dst_ip: 0x08080808,    // 8.8.8.8
        src_port: 54321,
        dst_port: 443,
        protocol: 6,           // TCP
    };
    
    group.bench_function("AHash tuple", |b| {
        b.iter(|| {
            let mut hasher = AHasher::default();
            tuple.hash(&mut hasher);
            black_box(hasher.finish())
        });
    });
    
    group.bench_function("XXH3 tuple", |b| {
        b.iter(|| {
            let mut hasher = Xxh3::default();
            hasher.write_u32(tuple.src_ip);
            hasher.write_u32(tuple.dst_ip);
            hasher.write_u16(tuple.src_port);
            hasher.write_u16(tuple.dst_port);
            hasher.write_u8(tuple.protocol);
            black_box(hasher.finish())
        });
    });
    
    group.finish();
}

fn bench_bulk_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bulk Hashing");
    
    let count = 1000;
    let packets: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let size = 64 + (i % 1436); // Variable packet sizes 64-1500
            (0..size).map(|j| ((i + j) % 256) as u8).collect()
        })
        .collect();
    
    group.throughput(Throughput::Elements(count as u64));
    
    group.bench_function("AHash bulk", |b| {
        b.iter(|| {
            packets.iter().map(|packet| {
                let mut hasher = AHasher::default();
                packet.hash(&mut hasher);
                hasher.finish()
            }).collect::<Vec<u64>>()
        });
    });
    
    group.bench_function("XXH3 bulk", |b| {
        b.iter(|| {
            packets.iter().map(|packet| {
                let mut hasher = Xxh3::default();
                hasher.write(packet);
                hasher.finish()
            }).collect::<Vec<u64>>()
        });
    });
    
    group.finish();
}

fn bench_hash_table_insert(c: &mut Criterion) {
    use std::collections::HashMap;
    use ahash::RandomState;
    
    let mut group = c.benchmark_group("Hash Table Insert");
    
    let entries = 10000;
    let keys: Vec<u64> = (0..entries).collect();
    
    group.bench_function("AHash HashMap insert", |b| {
        b.iter(|| {
            let mut map: HashMap<u64, u64, RandomState> = HashMap::with_hasher(RandomState::new());
            for &key in &keys {
                map.insert(black_box(key), black_box(key * 2));
            }
            map
        });
    });
    
    group.bench_function("Standard HashMap insert", |b| {
        b.iter(|| {
            let mut map: HashMap<u64, u64> = HashMap::new();
            for &key in &keys {
                map.insert(black_box(key), black_box(key * 2));
            }
            map
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_ahash,
    bench_xxh3,
    bench_hash_comparison,
    bench_connection_tuple_hash,
    bench_bulk_hashing,
    bench_hash_table_insert
);

criterion_main!(benches);
