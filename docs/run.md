# sennel run

[Back to the README](../README.md)

Start a program with entry fields in its environment. The secrets go straight from the vault to the
program, never through the clipboard, a shell variable or your history.

```sh
sennel run -e PGPASSWORD=prod-postgres -- psql -h db.example.com -U app mydb
sennel run -e AWS_ACCESS_KEY_ID=aws::username -e AWS_SECRET_ACCESS_KEY=aws -- terraform apply
sennel run -e STRIPE_KEY="stripe::api key" -- npm run deploy
```

Each `-e VAR=NEEDLE` sets `VAR` to the password of the entry `NEEDLE` finds. Add `::FIELD` for
another field:

| Field              | What `VAR` gets                                   |
| ------------------ | ------------------------------------------------- |
| `::password`       | the password. The default when no field is named  |
| `::username`       | the username. `::user` works too                  |
| `::url`            | the url                                           |
| `::otp`            | the current one-time code, never the seed         |
| `::<name>`         | the custom field called `<name>`, exactly         |

The last `::` splits off the field, so a needle may contain one. A custom field named like a fixed
one, such as `username`, is reached by the fixed meaning, not the custom one.

The needle works as it does for [sennel get](get.md): an exact title wins, then a single fuzzy match.

## What it checks before running anything

Every `-e` is checked before the password prompt. A variable name that is not letters, digits and
`_`, a missing needle or field, or the same variable twice is refused first. Then every entry is
read before the program starts, so a typo or a missing field never runs the program with a variable
missing.

## The password

From a terminal, `run` prompts, and the program then gets the terminal as usual. Otherwise it reads
the first line of stdin, a pipe or a redirected file, and the program gets the rest:

```sh
security find-generic-password -a "$USER" -s sennel-master -w | sennel run -e PGPASSWORD=prod -- psql
```

[Unlocking from the system keychain](keychain.md) covers storing the master password that way.

## Exit codes

| Code | Meaning                                                |
| ---- | ------------------------------------------------------ |
| any  | the program ran, and this is its exit code             |
| 1    | Sennel failed first: bad password, no vault, bad `-e`, a missing field |
| 2    | a needle matched more than one entry                   |
| 3    | a needle matched nothing                               |
| 126  | the program was found but could not start              |
| 127  | the program was not found                              |

A program can exit 1, 2 or 3 itself. Sennel's own failures always print `Error:` or a match message on
stderr first, so a script that needs to tell them apart can check stderr.

## What to know about environment variables

On Linux and macOS, Sennel becomes the program, the way `exec` does in a shell. Its signals and exit
code are the program's own, and no copy of the vault stays behind in a Sennel process.

The variables live in the program's environment for as long as it runs. Other processes running as
you can read another process's environment: `/proc/<pid>/environ` on Linux, `ps eww` on macOS.
Root can always read it. That is the same exposure as `PGPASSWORD=... psql` typed by hand, without
the shell history. Programs that start their own children pass the variables on to them.

The program also inherits Sennel's hardening: core dumps are off, so a crash of the program cannot
write its secrets to disk.
