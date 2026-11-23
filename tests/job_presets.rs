//! Built-in `auto_job_update` presets: the documented contract of the
//! rendered scripts and their behavior under `/bin/sh` with a stub `curl`.

use std::{
    fs::{self, File, Permissions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime},
};

use svpn::job::Reload;

const PRESETS: [Reload; 2] = [Reload::Geo, Reload::Country];
/// The row floor the scripts enforce before installing a download.
const ROWS: usize = 100_000;

// ── documented contract ──

#[test]
fn geo_preset_matches_the_documented_contract() {
    let spec = svpn::job::preset_update(Reload::Geo);
    assert_eq!(spec.label, "geo-update");
    assert_eq!(spec.every, Duration::from_secs(3600));
    assert_eq!(spec.timeout, Duration::from_secs(600));
    assert_eq!(spec.reload, vec![Reload::Geo]);
    let check = spec.run_if.as_deref().unwrap();
    assert!(check.contains("db=$SVPN_GEO_DB"));
    // BSD stat with the GNU fallback: the answer is validated, not the code.
    assert!(check.contains("stat -f %m") && check.contains("stat -c %Y"));
    // OpenWrt ships no stat: `date -r FILE` reads the age there.
    assert!(check.contains(r#"date -r "$db" +%s"#));
    let run = &spec.run;
    assert!(run.contains("dbip-asn-lite"));
    assert!(run.contains(r"geo.XXXXXX"));
    assert!(run.contains("104857600"));
    // 100 MiB for the download, ~477 MiB once the archive is unpacked.
    assert!(run.contains("ulimit -f 204800") && run.contains("ulimit -f 976563"));
    assert!(run.contains(r",[0-9]+'")); // ASN rows end in a number
    assert!(run.contains(r#""$rows" -ge 100000"#));
    // Atomic install only after validation; no partial files on failure.
    assert!(run.contains(r#"trap 'rm -f "$tmp" "$tmp.gz"' EXIT"#));
    assert!(run.rfind("mv \"$tmp\" \"$db\"").unwrap() > run.find("valid rows").unwrap() - 100);
}

#[test]
fn country_preset_matches_the_documented_contract() {
    let spec = svpn::job::preset_update(Reload::Country);
    assert_eq!(spec.label, "country-update");
    assert_eq!(spec.reload, vec![Reload::Country]);
    let check = spec.run_if.as_deref().unwrap();
    assert!(check.contains("db=$SVPN_COUNTRY_DB"));
    // A daily source is refreshed by age, not by the month in its file name.
    assert!(check.contains("-lt 86400") && !check.contains("file_month"));
    assert!(check.contains(r#"date -r "$db" +%s"#));
    let run = &spec.run;
    assert!(
        run.contains("ip-location-db/releases/download/latest/server-country-ipv4.csv"),
        "{run}"
    );
    // The source serves a plain CSV: nothing to unpack.
    assert!(!run.contains("gzip") && run.contains(r#"-o "$tmp" ;;"#));
    // The quota is the kernel's file-size limit, not a client flag: OpenWrt's
    // uclient-fetch and BusyBox wget know no `-Q`.
    assert!(
        run.contains("ulimit -f 204800") && run.contains(r#"openwrt) wget -q -O "$tmp" "$url" ;;"#),
        "{run}"
    );
    assert!(run.contains(r"country.XXXXXX"));
    // Country rows end with a two-letter code; ASN rows carry a number.
    assert!(run.contains("[A-Z][A-Z]$"));
}

// ── behavior under /bin/sh ──

#[test]
fn presets_skip_fresh_databases_and_request_stale_ones() {
    for reload in PRESETS {
        let spec = svpn::job::preset_update(reload);
        let check = spec.run_if.as_deref().unwrap();
        let sandbox = Sandbox::new(&format!("freshness-{}", spec.label));

        // Missing database: work to do. No database configured: never a blind run.
        assert!(
            sandbox
                .sh(check, Some(db_variable(reload)), None)
                .status
                .success(),
            "{}: a missing database is stale",
            spec.label
        );
        assert_eq!(
            sandbox.sh(check, None, None).status.code(),
            Some(1),
            "{}: without a path there is nothing to check",
            spec.label
        );

        // Written now: its month is the current one on any day of the month.
        sandbox.write_db(SystemTime::now());
        assert!(
            !sandbox
                .sh(check, Some(db_variable(reload)), None)
                .status
                .success(),
            "{}: a fresh database is skipped",
            spec.label
        );

        // Past the daily issue; past the monthly one for any day of the month.
        let stale = match reload {
            Reload::Country => 2,
            Reload::Geo => 40,
        };
        sandbox.write_db(SystemTime::now() - Duration::from_secs(stale * 24 * 3600));
        assert!(
            sandbox
                .sh(check, Some(db_variable(reload)), None)
                .status
                .success(),
            "{}: a stale database is refreshed",
            spec.label
        );
    }
}

#[test]
fn presets_read_the_file_age_where_no_stat_exists() {
    for reload in PRESETS {
        let spec = svpn::job::preset_update(reload);
        let check = spec.run_if.as_deref().unwrap();
        let sandbox = Sandbox::new(&format!("no-stat-{}", spec.label));
        sandbox.write_db(SystemTime::now() - Duration::from_secs(40 * 24 * 3600));
        // OpenWrt: no stat on PATH. BusyBox and GNU `date -r FILE` read a
        // file's age; BSD date cannot, and an unknown age skips the run.
        let only_date = sandbox.only_tool("date");
        let probe = Command::new("/bin/sh")
            .args(["-c", "date -r \"$1\" +%s", "date"])
            .arg(&sandbox.db)
            .env("PATH", &only_date)
            .output()
            .unwrap();
        let reads_age = String::from_utf8_lossy(&probe.stdout)
            .trim()
            .parse::<u64>()
            .is_ok();

        let output = sandbox.sh(check, Some(db_variable(reload)), Some(&only_date));

        if reads_age {
            assert!(
                output.status.success(),
                "{}: a stale database is refreshed through date -r",
                spec.label
            );
        } else {
            assert_eq!(output.status.code(), Some(1), "{}", spec.label);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!("{}: cannot read the age of", spec.label)),
                "{stderr}"
            );
        }
    }
}

#[test]
fn presets_install_a_valid_download() {
    for reload in PRESETS {
        let spec = svpn::job::preset_update(reload);
        let sandbox = Sandbox::new(&format!("install-{}", spec.label));
        let csv = valid_rows(reload);
        let download = match reload {
            Reload::Geo => gzip(csv.as_bytes()),
            Reload::Country => csv.clone().into_bytes(),
        };
        fs::write(&sandbox.body, download).unwrap();

        let output = sandbox.sh(&spec.run, Some(db_variable(reload)), None);

        assert!(
            output.status.success(),
            "{}: {}",
            spec.label,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("{}: {ROWS} rows installed\n", spec.label)
        );
        assert_eq!(fs::read_to_string(&sandbox.db).unwrap(), csv);
        // The staging file and the unpacked archive are gone.
        assert_eq!(sandbox.installed(), vec!["db.csv"], "{}", spec.label);
    }
}

#[test]
fn presets_keep_the_previous_database_on_garbage() {
    for reload in PRESETS {
        let spec = svpn::job::preset_update(reload);
        let sandbox = Sandbox::new(&format!("garbage-{}", spec.label));
        fs::write(&sandbox.db, "previous database\n").unwrap();
        // The line count of a real download: for the archive even gzip fails.
        fs::write(
            &sandbox.body,
            "<html>mirror error page</html>\n".repeat(ROWS),
        )
        .unwrap();

        let output = sandbox.sh(&spec.run, Some(db_variable(reload)), None);

        assert!(!output.status.success(), "{}", spec.label);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if reload == Reload::Country {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                stderr.contains("country-update: suspicious download (0 valid rows)"),
                "{stderr}"
            );
        }
        assert_eq!(
            fs::read_to_string(&sandbox.db).unwrap(),
            "previous database\n"
        );
        assert_eq!(sandbox.installed(), vec!["db.csv"], "{}", spec.label);
    }
}

#[test]
fn presets_stop_an_oversized_download() {
    for reload in PRESETS {
        let spec = svpn::job::preset_update(reload);
        let sandbox = Sandbox::new(&format!("oversized-{}", spec.label));
        fs::write(&sandbox.db, "previous database\n").unwrap();
        // Sparse: nothing is written until the kernel's file-size limit bites.
        File::create(&sandbox.body)
            .unwrap()
            .set_len(101 << 20)
            .unwrap();

        let output = sandbox.sh(&spec.run, Some(db_variable(reload)), None);

        assert!(!output.status.success(), "{}", spec.label);
        assert_eq!(
            fs::read_to_string(&sandbox.db).unwrap(),
            "previous database\n"
        );
        assert_eq!(sandbox.installed(), vec!["db.csv"], "{}", spec.label);
    }
}

#[test]
fn country_gate_refreshes_a_database_stamped_in_the_future() {
    // A router clock that ran ahead when the file landed must not keep it
    // fresh until the clock catches up.
    let spec = svpn::job::preset_update(Reload::Country);
    let sandbox = Sandbox::new("future");
    sandbox.write_db(SystemTime::now() + Duration::from_secs(30 * 24 * 3600));

    let output = sandbox.sh(
        spec.run_if.as_deref().unwrap(),
        Some("SVPN_COUNTRY_DB"),
        None,
    );

    assert!(output.status.success(), "{}", output.status);
}

/// The job variable naming a preset's database.
fn db_variable(reload: Reload) -> &'static str {
    match reload {
        Reload::Geo => "SVPN_GEO_DB",
        Reload::Country => "SVPN_COUNTRY_DB",
    }
}

/// `ROWS` rows in the source's real shape: a network, its last address, the payload.
fn valid_rows(reload: Reload) -> String {
    let payload = match reload {
        Reload::Geo => "13335",
        Reload::Country => "AU",
    };
    format!("1.0.0.0,1.0.0.255,{payload}\n").repeat(ROWS)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut child = Command::new("gzip")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap().stdout
}

/// Scratch directory holding the database, the download body and a `curl`
/// stub that copies the body to `-o FILE` instead of using the network. The
/// name has a space: the scripts must keep quoting their paths.
struct Sandbox {
    dir: PathBuf,
    db: PathBuf,
    body: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("svpn job preset {tag} {}", std::process::id()));
        let sandbox = Self {
            db: dir.join("db.csv"),
            body: dir.join("body"),
            dir,
        };
        fs::create_dir_all(sandbox.dir.join("bin")).unwrap();
        sandbox.tool("bin", "curl", "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  [ \"$1\" = -o ] && cp \"$SVPN_STUB_BODY\" \"$2\"\n  shift\ndone\n");
        sandbox
    }

    /// An executable script first on PATH under `folder`.
    fn tool(&self, folder: &str, name: &str, script: &str) {
        let path = self.dir.join(folder).join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
    }

    /// The empty database with its modification time `at` (`SystemTime::now()`
    /// leaves it fresh).
    fn write_db(&self, at: SystemTime) {
        File::create(&self.db).unwrap().set_modified(at).unwrap();
    }

    /// A PATH holding the real `name` and nothing else.
    fn only_tool(&self, name: &str) -> PathBuf {
        let folder = self.dir.join("only");
        fs::create_dir_all(&folder).unwrap();
        let real = std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|dir| dir.join(name))
                    .find(|path| path.is_file())
            })
            .unwrap_or_else(|| panic!("no {name} on PATH"));
        std::os::unix::fs::symlink(real, folder.join(name)).unwrap();
        folder
    }

    /// `/bin/sh -c` with the job environment: `SVPN_OS` outside the openwrt
    /// branch, the database variable (`None` leaves it unset), the stub body
    /// and the stub `curl` first on PATH. `path` replaces PATH altogether.
    fn sh(&self, script: &str, db_variable: Option<&str>, path: Option<&Path>) -> Output {
        let mut command = Command::new("/bin/sh");
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path = match path {
            Some(path) => path.as_os_str().to_owned(),
            None => std::env::join_paths(
                [self.dir.join("bin")]
                    .into_iter()
                    .chain(std::env::split_paths(&inherited)),
            )
            .unwrap(),
        };
        command
            .args(["-c", script])
            .env("SVPN_OS", "test")
            .env("SVPN_STUB_BODY", &self.body)
            .env("PATH", path);
        match db_variable {
            Some(name) => command.env(name, &self.db),
            None => command
                .env_remove("SVPN_GEO_DB")
                .env_remove("SVPN_COUNTRY_DB"),
        };
        command.output().unwrap()
    }

    /// File names left in the directory besides the sandbox's own.
    fn installed(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| !matches!(name.as_str(), "bin" | "body" | "only"))
            .collect();
        names.sort();
        names
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
