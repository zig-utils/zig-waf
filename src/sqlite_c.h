/* Translation unit for the system SQLite (#57). zig cc resolves <sqlite3.h>
 * from the platform SDK when the module links libc; the library itself is
 * linked with -lsqlite3. Kept as a shim so build.zig can point addTranslateC at
 * a repo-local header rather than an absolute SDK path. */
#include <sqlite3.h>
