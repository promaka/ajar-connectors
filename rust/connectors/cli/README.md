<!-- SPDX-License-Identifier: Apache-2.0 -->
# ajar-connectors

Installs, enrols and runs Ajar connectors on one machine. The operator sends an
invite from Core; this command turns it into a running connector.

## Setup

Unpack the release tarball (or a package tar from the operator) and run its
binary once:

```sh
sudo ./ajar-connectors setup          # /opt/ajar-connectors, for every user
./ajar-connectors setup               # ~/.ajar-connectors, for you only
./ajar-connectors setup --dir <dir>   # another folder
```

For every user, `setup` links `/usr/local/bin/ajar-connectors`, and every
command then runs with `sudo`, since the folder belongs to root. For one user it
prints the line that puts the command on your PATH. A package tar's `packages/`
folder is copied in, so its connectors install without a network.

## A connector from an invite

```sh
sudo ajar-connectors install adsb          # from packages/, a binary file, or GitHub
sudo ajar-connectors join radar-1.invite   # check, preflight, create and start
sudo ajar-connectors status
```

Without `sudo` for a setup in your own folder.

`join` refuses an invite for a connector type that is not installed, and names
the `install` command. An egress connector also needs a target, asked for or
given with `--target`.

When the connector's keys must never leave this machine, ask for an invite
instead:

```sh
ajar-connectors request adsb radar-1  # writes radar-1.request for the operator
ajar-connectors join radar-1.invite   # the invite that answers it
```

## Commands

| Command | Does |
|---|---|
| `setup` | creates the root folder and puts the command on the PATH |
| `install <type>[@version]` | installs from `packages/`, a binary file `./ajar-<type>`, or an online release |
| `update [<type>]` | installs newer versions and asks per instance whether to move it |
| `list [--available]` | what is installed, in `packages/` and in the current folder; online with `--available` |
| `uninstall <type>@<version>` | removes a version no instance uses |
| `join <file>.invite` | enrols and starts a connector; `--check` changes nothing |
| `request <type> <id>` | makes the keys here and the request file for the operator |
| `run <type>[@version] <config>` | runs a connector in the foreground with a config file |
| `start`, `stop`, `logs`, `remove` `<id>` | one instance |
| `status` | every instance and whether it runs |
| `check <id>`, `check --config <file> [--consumer <id>]` | the preflight `join` runs |

Every question has a flag, so scripts can pass flags instead. `setup`,
`install`, `update`, `uninstall`, `join`, `request` and `remove` show a plan
first and ask to continue; `--yes` skips that.

## Folders

```
<root>/
  ajar-connectors.toml
  bin/ajar-connectors
  connectors/<type>/<version>/    installed connector types
  packages/                       release tarballs with their .sha256
  instances/<connector-id>/       one per enrolled connector
```

An instance folder holds the invite's certificates and keys, `instance.toml`,
`settings.toml`, the `config.toml` written at every start, the log and the pid.
Local settings such as `marking`, `spool` or a consumer's `[tak]` table go in
the instance's `settings.toml`; a setting the invite decides is refused there.

## Limits

- Connectors run as background processes with a pid file. Nothing restarts a
  connector after a crash or a reboot.
- `start` runs on Linux only. On other systems use `run`.
- Connectors are released for x86_64 and aarch64 Linux with glibc.
