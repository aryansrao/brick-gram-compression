// Brick compressor (Re-Pair style) with:
//  - AES-256-GCM optional encryption
//  - CRC32 verification
//  - Parallel pair counting (rayon)
//  - Parallel replacement step using chunking + Atomic flags
//  - Single-line rich progress UI
//
// Build: cargo build --release

use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use rayon::prelude::*;
use hashbrown::HashMap;

use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

type Sym = u32;
const BASE_ID: Sym = 256;
const MAGIC: &[u8; 4] = b"BRCK";
const VERSION: u8 = 1;
const FLAG_ENCRYPTED: u8 = 0x1;
const FILENAME_XOR_KEY: u8 = 0xA5;

// ---------- CRC32 ----------
fn crc32_table() -> [u32; 256] {
    const POLY: u32 = 0xEDB88320;
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut crc = i as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    table
}
fn crc32_of_slice(bytes: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    !crc
}

// ---------- uleb128 helpers ----------
fn write_uleb128_to<W: Write>(mut w: W, mut val: u64) -> io::Result<()> {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            w.write_all(&[byte | 0x80])?;
        } else {
            w.write_all(&[byte])?;
            break;
        }
    }
    Ok(())
}
fn read_uleb128_from<R: Read>(mut r: R) -> io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let mut buf = [0u8; 1];
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF in uleb"));
        }
        let byte = buf[0];
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

// ---------- Parallel pair counting ----------
fn count_pairs_parallel(seq: &Vec<Sym>) -> HashMap<(Sym, Sym), usize> {
    let n = seq.len();
    let mut global: HashMap<(Sym, Sym), usize> = HashMap::new();
    if n < 2 {
        return global;
    }

    let merged = (0..(n - 1))
        .into_par_iter()
        .fold(
            || HashMap::with_capacity(1024),
            |mut local: HashMap<(Sym, Sym), usize>, i| {
                let p = (seq[i], seq[i + 1]);
                *local.entry(p).or_insert(0) += 1;
                local
            },
        )
        .reduce(
            || HashMap::with_capacity(1024),
            |mut a: HashMap<(Sym, Sym), usize>, b: HashMap<(Sym, Sym), usize>| {
                for (k, v) in b {
                    *a.entry(k).or_insert(0) += v;
                }
                a
            },
        );

    global = merged;
    global
}

// ---------- Parallel replacement (chunked, safe) ----------
// Mark all replacement start positions in a flags array (AtomicU8 per possible start).
// Then each chunk reconstructs its output in parallel, accounting for boundary consumption.
fn replace_pair_parallel(seq: &Vec<Sym>, pair: (Sym, Sym), new_sym: Sym) -> Vec<Sym> {
    let n = seq.len();
    if n < 2 {
        return seq.clone();
    }
    let (a, b) = pair;
    let starts = n - 1;
    // create flags default 0
    let mut flags: Vec<AtomicU8> = Vec::with_capacity(starts);
    for _ in 0..starts {
        flags.push(AtomicU8::new(0));
    }

    // mark starts in parallel
    (0..starts).into_par_iter().for_each(|i| {
        if seq[i] == a && seq[i + 1] == b {
            flags[i].store(1, Ordering::Relaxed);
        }
    });

    // define chunking over symbols (not starts) because output size varies
    let threads = rayon::current_num_threads();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut chunk_size = n / threads;
    if chunk_size == 0 { chunk_size = 1; }
    let mut s = 0usize;
    while s < n {
        let e = (s + chunk_size).min(n);
        ranges.push((s, e));
        s = e;
    }

    // Each chunk builds local Vec<Sym>
    let local_outputs: Vec<Vec<Sym>> = ranges.into_par_iter().map(|(start_idx, end_idx)| {
        let mut out: Vec<Sym> = Vec::with_capacity(end_idx - start_idx + 4);
        let mut i = start_idx;

        // if previous chunk ended with a replacement covering 'i' as second symbol, skip it
        if i > 0 {
            if flags[i - 1].load(Ordering::Relaxed) == 1 {
                // previous start replaced (consumes i), so skip this symbol (it was consumed)
                i += 1;
            }
        }

        while i < end_idx {
            // if possible start here and flagged, perform replacement and skip next symbol
            if i < n - 1 && flags[i].load(Ordering::Relaxed) == 1 {
                out.push(new_sym);
                i += 2;
            } else {
                out.push(seq[i]);
                i += 1;
            }
        }

        // Special case: chunk might stop leaving last symbol that participates in a pair starting inside chunk
        // That symbol may be consumed by next chunk's replacement start; that's fine because next chunk will skip it.
        out
    }).collect();

    // concatenate in order
    let mut res: Vec<Sym> = Vec::new();
    for chunk in local_outputs {
        res.extend(chunk);
    }
    res
}

// Fallback sequential replacement
fn replace_pair_seq(seq: &Vec<Sym>, pair: (Sym, Sym), new_sym: Sym) -> Vec<Sym> {
    let (a,b) = pair;
    let mut out = Vec::with_capacity(seq.len());
    let mut i = 0usize;
    while i < seq.len() {
        if i + 1 < seq.len() && seq[i] == a && seq[i+1] == b {
            out.push(new_sym);
            i += 2;
        } else {
            out.push(seq[i]);
            i += 1;
        }
    }
    out
}

fn decode_sequence(mut seq: Vec<Sym>, rules: &Vec<(Sym, Sym)>) -> Vec<u8> {
    let mut rhs_map: HashMap<Sym, (Sym, Sym)> = HashMap::new();
    for (i, &(a, b)) in rules.iter().enumerate() {
        rhs_map.insert(BASE_ID + (i as Sym), (a, b));
    }
    let mut changed = true;
    while changed {
        changed = false;
        let mut out: Vec<Sym> = Vec::with_capacity(seq.len());
        for &s in seq.iter() {
            if s >= BASE_ID {
                if let Some(&(a, b)) = rhs_map.get(&s) {
                    out.push(a);
                    out.push(b);
                    changed = true;
                } else {
                    out.push(s);
                }
            } else {
                out.push(s);
            }
        }
        seq = out;
    }
    seq.into_iter().map(|x| x as u8).collect()
}

// ---------- payload serialization ----------
fn build_payload(rules: &Vec<(Sym, Sym)>, seq: &Vec<Sym>, original_name: &str) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    write_uleb128_to(&mut buf, rules.len() as u64)?;
    for &(a, b) in rules.iter() {
        write_uleb128_to(&mut buf, a as u64)?;
        write_uleb128_to(&mut buf, b as u64)?;
    }
    write_uleb128_to(&mut buf, seq.len() as u64)?;
    for &s in seq.iter() {
        write_uleb128_to(&mut buf, s as u64)?;
    }
    let name_bytes = original_name.as_bytes();
    let obf: Vec<u8> = name_bytes.iter().map(|&b| b ^ FILENAME_XOR_KEY).collect();
    write_uleb128_to(&mut buf, obf.len() as u64)?;
    buf.extend_from_slice(&obf);
    let crc = crc32_of_slice(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    Ok(buf)
}
fn parse_payload(mut payload: &[u8]) -> io::Result<(Vec<(Sym, Sym)>, Vec<Sym>, String, u32)> {
    let rules_cnt = read_uleb128_from(&mut payload)? as usize;
    let mut rules: Vec<(Sym, Sym)> = Vec::with_capacity(rules_cnt);
    for _ in 0..rules_cnt {
        let a = read_uleb128_from(&mut payload)? as Sym;
        let b = read_uleb128_from(&mut payload)? as Sym;
        rules.push((a, b));
    }
    let seq_len = read_uleb128_from(&mut payload)? as usize;
    let mut seq: Vec<Sym> = Vec::with_capacity(seq_len);
    for _ in 0..seq_len {
        let s = read_uleb128_from(&mut payload)? as Sym;
        seq.push(s);
    }
    let name_len = read_uleb128_from(&mut payload)? as usize;
    let mut obf = vec![0u8; name_len];
    payload.read_exact(&mut obf)?;
    let mut crc_bytes = [0u8; 4];
    payload.read_exact(&mut crc_bytes)?;
    let crc = u32::from_le_bytes(crc_bytes);
    let name_bytes: Vec<u8> = obf.into_iter().map(|b| b ^ FILENAME_XOR_KEY).collect();
    let original_name = String::from_utf8_lossy(&name_bytes).into_owned();
    Ok((rules, seq, original_name, crc))
}

// ---------- .brick write/read with AES-GCM option ----------
fn write_brick(path: &str, original_name: &str, rules: &Vec<(Sym, Sym)>, seq: &Vec<Sym>, encrypt: bool, passphrase: Option<&str>) -> io::Result<()> {
    let payload = build_payload(rules, seq, original_name)?;
    let mut f = File::create(path)?;
    f.write_all(MAGIC)?;
    f.write_all(&[VERSION])?;
    let mut flags: u8 = 0;
    if encrypt { flags |= FLAG_ENCRYPTED; }
    f.write_all(&[flags])?;
    if encrypt {
        let pass = passphrase.expect("passphrase required for encryption");
        let key_bytes = Sha256::digest(pass.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "cipher init failed"))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, payload.as_ref()).map_err(|_| io::Error::new(io::ErrorKind::Other, "encryption failed"))?;
        f.write_all(&nonce_bytes)?;
        write_uleb128_to(&mut f, ciphertext.len() as u64)?;
        f.write_all(&ciphertext)?;
    } else {
        write_uleb128_to(&mut f, payload.len() as u64)?;
        f.write_all(&payload)?;
    }
    Ok(())
}

fn read_brick_and_decode(path: &str, passphrase: Option<&str>) -> io::Result<(String, Vec<u8>)> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }
    let mut ver = [0u8; 1];
    f.read_exact(&mut ver)?;
    if ver[0] != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported version"));
    }
    let mut flags = [0u8; 1];
    f.read_exact(&mut flags)?;
    let encrypted = (flags[0] & FLAG_ENCRYPTED) != 0;
    let payload: Vec<u8> = if encrypted {
        let mut nonce_bytes = [0u8; 12];
        f.read_exact(&mut nonce_bytes)?;
        let cipher_len = read_uleb128_from(&mut f)? as usize;
        let mut cipher_text = vec![0u8; cipher_len];
        f.read_exact(&mut cipher_text)?;
        let pass = passphrase.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "passphrase required for decryption"))?;
        let key_bytes = Sha256::digest(pass.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_slice()).map_err(|_| io::Error::new(io::ErrorKind::Other, "cipher init failed"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plain = cipher.decrypt(nonce, cipher_text.as_ref()).map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption failed (wrong passphrase or corrupted)"))?;
        plain
    } else {
        let payload_len = read_uleb128_from(&mut f)? as usize;
        let mut payload = vec![0u8; payload_len];
        f.read_exact(&mut payload)?;
        payload
    };
    let (rules, seq, original_name, crc_in_file) = parse_payload(&payload[..])?;
    let crc_calc = crc32_of_slice(&payload[..payload.len() - 4]);
    if crc_calc != crc_in_file {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "CRC mismatch — file corrupted"));
    }
    let decoded = decode_sequence(seq, &rules);
    Ok((original_name, decoded))
}

// ---------- helpers ----------
fn human_bytes(n: usize) -> String {
    let mut f = n as f64;
    let units = ["B", "KB", "MB", "GB"];
    let mut i = 0usize;
    while f >= 1024.0 && i + 1 < units.len() {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{}{}", n, units[i])
    } else {
        format!("{:.1}{}", f, units[i])
    }
}
fn progress_bar(frac: f64, width: usize) -> String {
    let f = frac.max(0.0).min(1.0);
    let filled = (f * width as f64).round() as usize;
    let mut s = String::new();
    s.push('[');
    for _ in 0..filled {
        s.push('█');
    }
    for _ in 0..(width - filled) {
        s.push('░');
    }
    s.push(']');
    s
}
fn write_file(path: &str, bytes: &[u8]) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn print_usage(name: &str) {
    eprintln!("Usage:");
    eprintln!("  {0} -c <in.txt>               # compress -> writes in.brick", name);
    eprintln!("  {0} -c <in.txt> -o out.brick  # compress to path", name);
    eprintln!("  {0} -c <in.txt> -e -p pass    # encrypt with passphrase", name);
    eprintln!("  {0} -d <in.brick>             # decompress (reads embedded filename)", name);
    eprintln!("  {0} -d <in.brick> -p pass     # decrypt and decompress", name);
    eprintln!("Options: --min-count N, --max-rules N (0=unlimited), --threads N");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).map(|s| s.as_str()).unwrap_or("brick-compressor");
    if args.len() == 1 {
        print_usage(prog);
        return Ok(());
    }

    // parse
    let mut i = 1usize;
    let mut compress_in: Option<String> = None;
    let mut decompress_in: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut min_count: usize = 2;
    let mut max_rules: usize = usize::MAX;
    let mut encrypt = false;
    let mut passphrase: Option<String> = None;
    let mut threads: Option<usize> = None;

    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--compress" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                compress_in = Some(args[i + 1].clone()); i += 2;
            }
            "-d" | "--decompress" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                decompress_in = Some(args[i + 1].clone()); i += 2;
            }
            "-o" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                out_path = Some(args[i + 1].clone()); i += 2;
            }
            "--min-count" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                min_count = args[i + 1].parse().unwrap_or(2); i += 2;
            }
            "--max-rules" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                let v = args[i + 1].parse::<u64>().unwrap_or(0);
                if v == 0 { max_rules = usize::MAX; } else { max_rules = v as usize; }
                i += 2;
            }
            "-e" | "--encrypt" => { encrypt = true; i += 1; }
            "-p" | "--pass" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                passphrase = Some(args[i + 1].clone()); i += 2;
            }
            "--threads" => {
                if i + 1 >= args.len() { print_usage(prog); return Ok(()); }
                threads = args[i + 1].parse().ok(); i += 2;
            }
            _ => { eprintln!("Unknown arg: {}", args[i]); print_usage(prog); return Ok(()); }
        }
    }

    if compress_in.is_none() && decompress_in.is_none() {
        print_usage(prog);
        return Ok(());
    }

    if let Some(n) = threads {
        let n_clamped = if n == 0 { 1 } else { n };
        rayon::ThreadPoolBuilder::new().num_threads(n_clamped).build_global().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "failed to set rayon threadpool")
        })?;
    }

    // decompress
    if let Some(inpath) = decompress_in {
        eprintln!("Decompressing '{}' ...", inpath);
        let pass = passphrase.as_deref();
        match read_brick_and_decode(&inpath, pass) {
            Ok((original_name, bytes)) => {
                let target = if let Some(o) = out_path { o } else { original_name.clone() };
                write_file(&target, &bytes)?;
                eprintln!("Wrote decompressed file: {} ({} bytes)", target, bytes.len());
            }
            Err(e) => eprintln!("Decompress error: {}", e),
        }
        return Ok(());
    }

    // compress branch
    let inpath = compress_in.unwrap();
    eprintln!("Compressing '{}' (min_count={}, max_rules={}, encrypt={}, threads={:?}) ...",
              inpath, min_count, if max_rules==usize::MAX {0} else {max_rules}, encrypt, threads);

    let input_bytes = {
        let mut v = Vec::new();
        let mut f = File::open(&inpath)?;
        f.read_to_end(&mut v)?;
        v
    };
    let original_len = input_bytes.len();
    eprintln!("Input size: {} bytes", original_len);

    // initial symbols and rules
    let mut seq: Vec<Sym> = input_bytes.iter().map(|&b| b as Sym).collect();
    let mut rules: Vec<(Sym, Sym)> = Vec::new();
    let mut next_sym: Sym = BASE_ID;

    // progress UI setup
    let start = Instant::now();
    let mut iter = 0usize;
    let bar_width = 24usize;
    let update_interval = Duration::from_millis(300);
    let mut last_update = Instant::now() - update_interval;
    let mut prev_line_len = 0usize;

    loop {
        if rules.len() >= max_rules { eprintln!("\nReached max rules {}", if max_rules==usize::MAX {0} else {max_rules}); break; }
        iter += 1;

        let counts = count_pairs_parallel(&seq);
        if counts.is_empty() { eprintln!("\nNo more pairs (iter={})", iter); break; }

        // choose best pair meeting min_count
        let mut best: Option<((Sym, Sym), usize)> = None;
        for (p, &c) in counts.iter() {
            if c >= min_count {
                match best {
                    None => best = Some((*p, c)),
                    Some((_, best_c)) if c > best_c => best = Some((*p, c)),
                    _ => {}
                }
            }
        }
        let (pair, freq) = match best {
            None => { eprintln!("\nNo pair meets min_count (iter={})", iter); break; }
            Some((p,f)) => (p,f),
        };

        // If sequence large, use parallel replacement; otherwise sequential
        let seq_len_for_parallel = 200_000; // heuristic threshold
        if seq.len() >= seq_len_for_parallel {
            seq = replace_pair_parallel(&seq, pair, next_sym);
        } else {
            seq = replace_pair_seq(&seq, pair, next_sym);
        }
        rules.push(pair);
        next_sym += 1;

        // UI update (rate limited)
        if last_update.elapsed() >= update_interval {
            let estimated_symbols = seq.len() + rules.len() * 2;
            let estimated_bytes = estimated_symbols;
            let pct = if original_len > 0 {
                100.0 * (original_len as f64 - estimated_bytes as f64) / original_len as f64
            } else { 0.0 };
            let pct_clamped = pct.max(0.0).min(99.9);
            let elapsed = start.elapsed().as_secs_f64().max(1e-9);
            let rules_per_sec = (rules.len() as f64) / elapsed;
            let bytes_reduced = (original_len as isize - estimated_bytes as isize).max(0) as f64;
            let speed_mb_s = (bytes_reduced / 1024.0 / 1024.0) / elapsed;
            let frac = pct_clamped / 100.0;
            let bar = progress_bar(frac, bar_width);
            let left = human_bytes(original_len);
            let right = human_bytes(estimated_bytes as usize);
            let eta = if rules_per_sec > 0.0 {
                let rem = (100.0 - pct_clamped) / 100.0;
                (rem * (elapsed / (pct_clamped.max(1e-6) / 100.0))).max(0.0)
            } else { f64::INFINITY };
            let eta_str = if eta.is_finite() { format!("ETA: {}s", eta.round() as u64) } else { "ETA: --".to_string() };

            let line = format!("{} {:>5.1}% | {}→{} | {:.1} rules/sec | {:.2} MB/s | freq={} | {}",
                               bar, pct_clamped, left, right, rules_per_sec, speed_mb_s, freq, eta_str);

            let mut out = String::new();
            out.push_str("\r");
            out.push_str(&line);
            if line.len() < prev_line_len {
                let pad = " ".repeat(prev_line_len - line.len());
                out.push_str(&pad);
            }
            prev_line_len = line.len();
            eprint!("{}", out);
            io::stderr().flush().ok();
            last_update = Instant::now();
        }
    }

    // final stats & write file
    let elapsed = start.elapsed().as_secs_f64();
    let estimated_symbols = seq.len() + rules.len() * 2;
    let estimated_bytes = estimated_symbols;
    let saved = (original_len as isize) - (estimated_bytes as isize);
    let ratio = if original_len > 0 { 100.0 * (estimated_bytes as f64) / original_len as f64 } else { 0.0 };
    let rules_per_sec_final = if elapsed > 0.0 { (rules.len() as f64) / elapsed } else { 0.0 };
    let speed_mb_s_final = if elapsed > 0.0 { ((original_len as f64 - estimated_bytes as f64).max(0.0) / 1024.0 / 1024.0) / elapsed } else { 0.0 };

    eprintln!("");
    eprintln!("Done. iterations={} rules={} final_seq_len={} time={:.2}s", iter, rules.len(), seq.len(), elapsed);
    eprintln!("Compression ratio (estimated): {:.1}% ({} → {})", ratio, human_bytes(original_len), human_bytes(estimated_bytes as usize));
    eprintln!("Estimated saved: {} bytes ({:.2}%) (heuristic)", saved, 100.0 * (original_len as f64 - estimated_bytes as f64) / original_len as f64);
    eprintln!("Speed: {:.2} MB/s | {:.2} rules/sec", speed_mb_s_final, rules_per_sec_final);

    // verify
    let decoded = decode_sequence(seq.clone(), &rules);
    if decoded == input_bytes {
        eprintln!("Verification: OK");
    } else {
        eprintln!("Verification: MISMATCH");
    }

    // output path
    let default_out = {
        let p = Path::new(&inpath);
        if let Some(stem) = p.file_stem() {
            if let Some(parent) = p.parent() {
                parent.join(format!("{}.brick", stem.to_string_lossy()))
            } else {
                Path::new(&format!("{}.brick", stem.to_string_lossy())).to_path_buf()
            }
        } else {
            Path::new(&format!("{}.brick", inpath)).to_path_buf()
        }
    };
    let outpath = out_path.unwrap_or(default_out.to_string_lossy().into_owned());
    let original_name = Path::new(&inpath).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| String::from("output"));

    if Path::new(&outpath).exists() {
        eprintln!("Warning: overwriting {}", outpath);
    }
    let pass = passphrase.as_deref();
    if encrypt && pass.is_none() {
        eprintln!("Encryption requested but no passphrase provided (-p). Aborting write.");
        return Ok(());
    }
    match write_brick(&outpath, &original_name, &rules, &seq, encrypt, pass) {
        Ok(()) => {
            if let Ok(meta) = fs::metadata(&outpath) {
                eprintln!("Wrote .brick file: {} ({} bytes)", outpath, meta.len());
            } else {
                eprintln!("Wrote .brick file: {}", outpath);
            }
        }
        Err(e) => eprintln!("Error writing .brick: {}", e),
    }

    Ok(())
}
