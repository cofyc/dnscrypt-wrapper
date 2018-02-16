# Releasing

## How to do a release

### Write change logs into CHANGELOG.md

First, generate change logs with following command:

```
git log --oneline --no-merges v<previous_version>..HEAD | sed -r 's/^\w+/-/g'
```

With some manual edits, write changes logs to CHANGELOG.md.

### Update version file

Update version.h file and commit with "release: bumped version to
<version>" as comment. Then create a PULL REQUEST with title "release
v<version>" as release PR and change logs as contents.

### Push a new tag and release

Create a tag with `git tag -m 'v<version>' v<version>"` command, and
push it to remote.

Go to https://github.com/cofyc/dnscrypt-wrapper/releases/new to create a
release on github.

Starting from 0.4.0, we don't attach .zip and .tar.bz2 source files in release,
because we don't have git sub-modules anymore, simply using github source
tarballs is enough.

## Version

Follow https://semver.org/.

Starting from 0.4.0, we don't omit minor and patch versions if they're
`0', see discussion in https://github.com/semver/semver/issues/237.
