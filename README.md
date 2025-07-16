# Why?
This script is designed for scenarios where you want to deduplicate incoming data against previously-seen data, but where that previously-seen data *is not available* to be hashed against (or you just don't want to recalculate all those hashes again). If the source data is available to you, or you want fine-grained control of the deduplication process, tools like `jdupes` or `DupeGuru` would serve you better.

# Warnings

## Not tested in production
This is a prototype script. Do not run in production, or against any data (incoming or archival) which you're afraid to lose.

Always backup your data. I assume no responsibility for failure to plan on your part.

## Don't delete your data!
By design, any files which this script has "seen" *twice* will always be considered duplicates, because the script makes no distinction as to "old" or "new" files, or their locations. When passing the `--delete` (or `-D`) flags, the script will therefore *delete your old files* if it "sees" those files a second time.

When ran without the `--delete` flag, the script is designed to ingest and hash all files to be deduplicated against.

When ran *with* the `--delete` flag, the script will also *delete* any files it has previously seen - even if those are your "old" files! So be careful.

By design, the `--delete` flag is only intended to be used on *incoming* data; never on pre-existing data which has any importance to you.
