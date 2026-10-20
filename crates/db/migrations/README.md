# Migrations (db crate)

APPLIED MIGRATIONS ARE IMMUTABLE after the first release: never edit a file that may have run on
any shared database; add a new forward file instead (`SSSS_NNNN_<desc>.sql`, one statement each).
The runner (`db::migrate`) refuses a changed file with `checksum mismatch at version N`.
Before the first release, only purely local databases may be rebuilt from scratch (owner decision).
